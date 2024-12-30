package scanner

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/spf13/viper"
	regexp "github.com/wasilibs/go-re2"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/messaging"
)

type GitLeaksScanner struct {
	detector *detect.Detector
	logger   *logger.Logger
	tracer   trace.Tracer
}

// NewGitLeaksScanner constructs and returns a GitLeaksScanner instance with the detector set up.
func NewGitLeaksScanner(
	ctx context.Context,
	broker messaging.Broker,
	logger *logger.Logger,
	tracer trace.Tracer,
) *GitLeaksScanner {
	detector := setupGitleaksDetector()
	if err := publishRulesOnStartup(ctx, broker, detector, logger, tracer); err != nil {
		logger.Error(ctx, "failed to publish rules on startup", "error", err)
	}

	return &GitLeaksScanner{
		detector: detector,
		logger:   logger,
		tracer:   tracer,
	}
}

// Scan clones the repository to a temporary directory and scans it for secrets.
// It ensures the cloned repository is cleaned up after scanning.
func (s *GitLeaksScanner) Scan(ctx context.Context, repoURL string) error {
	// Parent span for the entire scan operation
	ctx, span := s.tracer.Start(ctx, "gitleaks.scan",
		trace.WithAttributes(
			attribute.String("repository.url", repoURL),
		))
	defer span.End()

	_, dirSpan := s.tracer.Start(ctx, "create_temp_dir")
	tempDir, err := os.MkdirTemp("", "gitleaks-scan-")
	if err != nil {
		dirSpan.RecordError(err)
		dirSpan.End()
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	dirSpan.End()

	defer func() {
		cleanupCtx, cleanupSpan := s.tracer.Start(ctx, "cleanup_temp_dir")
		if err := os.RemoveAll(tempDir); err != nil {
			cleanupSpan.RecordError(err)
			s.logger.Error(cleanupCtx, "failed to cleanup temp directory", "error", err)
		}
		cleanupSpan.End()
	}()

	cloneCtx, cloneSpan := s.tracer.Start(ctx, "git.clone",
		trace.WithAttributes(
			attribute.String("repository.url", repoURL),
			attribute.String("clone.path", tempDir),
		))
	if err := cloneRepo(cloneCtx, repoURL, tempDir); err != nil {
		cloneSpan.RecordError(err)
		cloneSpan.End()
		return fmt.Errorf("failed to clone repository: %w", err)
	}
	cloneSpan.End()

	_, cmdSpan := s.tracer.Start(ctx, "git.setup_log_cmd")
	gitCmd, err := sources.NewGitLogCmd(tempDir, "")
	if err != nil {
		cmdSpan.RecordError(err)
		cmdSpan.End()
		return fmt.Errorf("failed to create git log command: %w", err)
	}
	cmdSpan.End()

	_, detectSpan := s.tracer.Start(ctx, "gitleaks.detect")
	findings, err := s.detector.DetectGit(gitCmd)
	if err != nil {
		detectSpan.RecordError(err)
		detectSpan.End()
		return fmt.Errorf("failed to scan repository: %w", err)
	}
	detectSpan.SetAttributes(
		attribute.Int("findings.count", len(findings)),
	)
	detectSpan.End()

	s.logger.Info(ctx, "found findings in repository", "repo_url", repoURL, "num_findings", len(findings))
	return nil
}

// cloneRepo clones a git repository to the specified directory
func cloneRepo(ctx context.Context, repoURL, dir string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", repoURL, dir)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w: %s", err, stderr.String())
	}

	return nil
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
	broker messaging.Broker,
	detector *detect.Detector,
	logger *logger.Logger,
	tracer trace.Tracer,
) error {
	ctx, span := tracer.Start(ctx, "gitleaks.publish_rules",
		trace.WithAttributes(
			attribute.Int("rules.count", len(detector.Config.Rules)),
		))
	defer span.End()

	// Convert and publish rules individually
	for _, rule := range detector.Config.Rules {
		domainRule := convertDetectorRuleToMessage(rule)
		if err := broker.PublishRule(ctx, domainRule); err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to publish rule %s: %w", rule.RuleID, err)
		}
	}

	logger.Info(ctx, "Published rules individually", "rules_count", len(detector.Config.Rules))
	return nil
}

func convertDetectorRuleToMessage(rule config.Rule) messaging.GitleaksRuleMessage {
	domainRule := messaging.GitleaksRule{
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

	return messaging.GitleaksRuleMessage{
		Rule: domainRule,
		Hash: domainRule.GenerateHash(),
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
func convertAllowlists(aws []config.Allowlist) []messaging.GitleaksAllowlist {
	dAll := make([]messaging.GitleaksAllowlist, 0, len(aws))
	for _, a := range aws {
		dAll = append(dAll, messaging.GitleaksAllowlist{
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
func matchConditionToDomain(mc config.AllowlistMatchCondition) messaging.AllowlistMatchCondition {
	switch mc {
	case config.AllowlistMatchOr:
		return messaging.MatchConditionOR
	case config.AllowlistMatchAnd:
		return messaging.MatchConditionAND
	default:
		return messaging.MatchConditionUnspecified
	}
}

// checkError terminates the program if an error is encountered during critical setup.
// This is used during initialization where recovery is not possible.
func checkError(msg string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}
