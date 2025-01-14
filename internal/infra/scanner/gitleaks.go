// Package scanner provides implementations of secret scanning engines for detecting sensitive
// information in data sources.
// It defines interfaces and adapters for integrating different scanning technologies while maintaining
// consistent detection patterns and reporting formats.
// The package handles scanning configuration, execution, and result aggregation while providing
// observability through structured logging and tracing.
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
	regexp "github.com/wasilibs/go-re2"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// metrics defines metrics operations for Git repository operations
type metrics interface {
	// ObserveRepoSize records the size of a cloned repository in bytes
	ObserveRepoSize(ctx context.Context, repoURI string, sizeBytes int64)

	// ObserveCloneTime records how long it took to clone a repository
	ObserveCloneTime(ctx context.Context, repoURI string, duration time.Duration)

	// IncCloneError increments the clone error counter for a repository
	IncCloneError(ctx context.Context, repoURI string)

	// ObserveFindings records the number of findings in a repository
	ObserveFindings(ctx context.Context, repoURI string, findings int)
}

// Gitleaks provides secret scanning functionality by wrapping the Gitleaks detection engine.
// It handles scanning repositories for potential secrets and sensitive information leaks
// while providing observability through logging and tracing.
type Gitleaks struct {
	detector *detect.Detector
	logger   *logger.Logger
	tracer   trace.Tracer
	metrics  metrics
}

// NewGitLeaksScanner creates a new Gitleaks scanner instance with a configured detector.
// It initializes the scanning engine and publishes the default ruleset on startup to ensure
// consistent detection patterns across scanner instances. The scanner uses OpenTelemetry
// for tracing and structured logging for observability.
func NewGitLeaksScanner(
	ctx context.Context,
	broker events.DomainEventPublisher,
	logger *logger.Logger,
	tracer trace.Tracer,
	metrics metrics,
) *Gitleaks {
	detector := setupGitleaksDetector()
	// Publish initial ruleset to ensure all scanners have consistent detection patterns
	if err := publishRulesOnStartup(ctx, broker, detector, logger, tracer); err != nil {
		logger.Error(ctx, "failed to publish rules on startup", "error", err)
	}

	return &Gitleaks{
		detector: detector,
		logger:   logger,
		tracer:   tracer,
		metrics:  metrics,
	}
}

// Scan clones the repository to a temporary directory and scans it for secrets.
// It ensures the cloned repository is cleaned up after scanning.
func (s *Gitleaks) Scan(ctx context.Context, task *dtos.ScanRequest) error {
	ctx, span := s.tracer.Start(ctx, "gitleaks_scanner.scanning.scan_repository",
		trace.WithAttributes(
			attribute.String("repository.url", task.ResourceURI),
			attribute.String("task.id", task.TaskID.String()),
			attribute.String("source.type", string(task.SourceType)),
		))
	defer span.End()

	_, dirSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.create_temp_dir")
	tempDir, err := os.MkdirTemp("", "gitleaks-scan-")
	if err != nil {
		dirSpan.RecordError(err)
		dirSpan.End()
		span.AddEvent("temp_dir_creation_failed")
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	dirSpan.End()
	span.AddEvent("temp_dir_created", trace.WithAttributes(
		attribute.String("temp_dir", tempDir),
	))

	defer func() {
		cleanupCtx, cleanupSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.cleanup_temp_dir")
		cleanupSpan.AddEvent("starting_cleanup")
		if err := os.RemoveAll(tempDir); err != nil {
			cleanupSpan.RecordError(err)
			cleanupSpan.AddEvent("cleanup_failed")
			s.logger.Error(cleanupCtx, "failed to cleanup temp directory", "error", err)
		} else {
			cleanupSpan.AddEvent("cleanup_successful")
		}
		cleanupSpan.End()
	}()

	cloneCtx, cloneSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.clone_repository",
		trace.WithAttributes(
			attribute.String("repository.url", task.ResourceURI),
			attribute.String("task.id", task.TaskID.String()),
			attribute.String("source.type", string(task.SourceType)),
			attribute.String("clone.path", tempDir),
		))
	defer cloneSpan.End()

	startTime := time.Now()
	if err := cloneRepo(cloneCtx, task.ResourceURI, tempDir); err != nil {
		cloneSpan.RecordError(err)
		cloneSpan.AddEvent("clone_failed")
		s.metrics.IncCloneError(ctx, task.ResourceURI)
		return fmt.Errorf("failed to clone repository: %w", err)
	}
	s.metrics.ObserveCloneTime(ctx, task.ResourceURI, time.Since(startTime))

	go s.calculateRepoSizeAsync(ctx, task, tempDir)

	cloneSpan.AddEvent("clone_successful")

	_, cmdSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.setup_git_log")
	gitCmd, err := sources.NewGitLogCmd(tempDir, "")
	if err != nil {
		cmdSpan.RecordError(err)
		cmdSpan.AddEvent("git_log_setup_failed")
		cmdSpan.End()
		return fmt.Errorf("failed to create git log command: %w", err)
	}
	cmdSpan.AddEvent("git_log_setup_successful")
	cmdSpan.End()

	_, detectSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.detect_secrets")
	detectSpan.AddEvent("starting_secret_detection")
	findings, err := s.detector.DetectGit(gitCmd)
	if err != nil {
		detectSpan.RecordError(err)
		detectSpan.AddEvent("secret_detection_failed")
		detectSpan.End()
		return fmt.Errorf("failed to scan repository: %w", err)
	}
	s.metrics.ObserveFindings(ctx, task.ResourceURI, len(findings))

	detectSpan.SetAttributes(
		attribute.Int("findings.count", len(findings)),
	)
	detectSpan.AddEvent("secret_detection_completed", trace.WithAttributes(
		attribute.Int("findings.count", len(findings)),
	))
	detectSpan.End()

	s.logger.Info(ctx, "found findings in repository", "repo_url", task.ResourceURI, "num_findings", len(findings))
	span.AddEvent("scan_completed", trace.WithAttributes(
		attribute.Int("findings.count", len(findings)),
	))
	return nil
}

// cloneRepo clones a git repository to the specified directory.
func cloneRepo(ctx context.Context, repoURL, dir string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", repoURL, dir)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w: %s", err, stderr.String())
	}

	return nil
}

// calculateRepoSizeAsync calculates the size of a repository asynchronously.
func (s *Gitleaks) calculateRepoSizeAsync(ctx context.Context, task *dtos.ScanRequest, tempDir string) {
	const defaultTimeout = 2 * time.Minute
	sizeCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	_, sizeSpan := s.tracer.Start(sizeCtx, "gitleaks_scanner.calculate_repo_size",
		trace.WithAttributes(
			attribute.String("repository.url", task.ResourceURI),
			attribute.String("task.id", task.TaskID.String()),
			attribute.String("clone.path", tempDir),
		))
	defer sizeSpan.End()

	size, err := getDirSize(sizeCtx, tempDir)
	if err != nil {
		if err != context.Canceled && err != context.DeadlineExceeded {
			sizeSpan.RecordError(err)
			s.logger.Warn(sizeCtx, "Failed to get repository size",
				"error", err,
				"repo", task.ResourceURI)
		}
		return
	}

	s.metrics.ObserveRepoSize(sizeCtx, task.ResourceURI, size)
	sizeSpan.AddEvent("size_calculation_complete",
		trace.WithAttributes(attribute.Int64("size_bytes", size)))

}

// getDirSize returns the total size of a directory in bytes
// It uses WalkDir for better performance and is context-aware
func getDirSize(ctx context.Context, path string) (int64, error) {
	var size int64
	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return err
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// setupGitleaksDetector initializes the Gitleaks detector using the embedded default configuration.
func setupGitleaksDetector() *detect.Detector {
	viper.SetConfigType("toml")
	err := viper.ReadConfig(bytes.NewBufferString(config.DefaultConfig))
	checkError("Failed to read embedded config", err)

	var vc config.ViperConfig
	err = viper.Unmarshal(&vc)
	checkError("Failed to unmarshal embedded config", err)

	cfg, err := vc.Translate()
	checkError("Failed to translate ViperConfig to Config", err)

	return detect.NewDetector(cfg)
}

// publishRulesOnStartup sends the current Gitleaks detection rules to the message broker
// when the scanner starts up. This ensures all components have access to the latest
// rule definitions for consistent secret detection.
func publishRulesOnStartup(
	ctx context.Context,
	broker events.DomainEventPublisher,
	detector *detect.Detector,
	logger *logger.Logger,
	tracer trace.Tracer,
) error {
	ctx, span := tracer.Start(ctx, "gitleaks_scanner.scanning.publish_rules",
		trace.WithAttributes(
			attribute.Int("rules.count", len(detector.Config.Rules)),
		))
	defer span.End()

	// Convert and publish rules individually
	for _, rule := range detector.Config.Rules {
		domainRule := convertDetectorRuleToMessage(rule)
		err := broker.PublishDomainEvent(ctx, rules.NewRuleUpdatedEvent(domainRule), events.WithKey(domainRule.Hash))
		if err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to publish rule %s: %w", rule.RuleID, err)
		}
	}

	logger.Info(ctx, "Published rules individually", "rules_count", len(detector.Config.Rules))
	return nil
}

func convertDetectorRuleToMessage(rule config.Rule) rules.GitleaksRuleMessage {
	domainRule := rules.GitleaksRule{
		RuleID:      rule.RuleID,
		Description: rule.Description,
		Entropy:     rule.Entropy,
		SecretGroup: rule.SecretGroup,
		Regex:       regexToString(rule.Regex),
		Path:        regexToString(rule.Path),
		Tags:        rule.Tags,
		Keywords:    rule.Keywords,
		Allowlists:  convertAllowlists(rule.Allowlists),
	}

	return rules.GitleaksRuleMessage{
		GitleaksRule: domainRule,
		Hash:         domainRule.GenerateHash(),
	}
}

// regexToString safely converts a compiled regular expression to its string pattern.
// Returns an empty string if the regex is nil.
func regexToString(re *regexp.Regexp) string {
	if re == nil {
		return ""
	}
	return re.String()
}

// convertAllowlists transforms Gitleaks allowlist configurations into a serializable format.
// Allowlists define exceptions to the detection rules to reduce false positives.
func convertAllowlists(aws []config.Allowlist) []rules.GitleaksAllowlist {
	dAll := make([]rules.GitleaksAllowlist, 0, len(aws))
	for _, a := range aws {
		dAll = append(dAll, rules.GitleaksAllowlist{
			Description:    a.Description,
			MatchCondition: matchConditionToDomain(a.MatchCondition),
			Commits:        a.Commits,
			PathRegexes:    regexSliceToStrings(a.Paths),
			Regexes:        regexSliceToStrings(a.Regexes),
			RegexTarget:    a.RegexTarget,
			StopWords:      a.StopWords,
		})
	}
	return dAll
}

// regexSliceToStrings converts a slice of compiled regular expressions to their string patterns.
// Nil regular expressions are skipped in the output.
func regexSliceToStrings(res []*regexp.Regexp) []string {
	var out []string
	for _, re := range res {
		if re != nil {
			out = append(out, re.String())
		}
	}
	return out
}

// matchConditionToDomain converts Gitleaks allowlist match conditions to our domain's
// representation. Match conditions determine how multiple allowlist criteria are combined.
func matchConditionToDomain(mc config.AllowlistMatchCondition) rules.AllowlistMatchCondition {
	switch mc {
	case config.AllowlistMatchOr:
		return rules.MatchConditionOR
	case config.AllowlistMatchAnd:
		return rules.MatchConditionAND
	default:
		return rules.MatchConditionUnspecified
	}
}

// checkError terminates the program if an error is encountered during critical setup.
// This is used during initialization where recovery is not possible.
func checkError(msg string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}
