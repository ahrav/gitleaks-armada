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
	"log"

	"github.com/spf13/viper"
	regexp "github.com/wasilibs/go-re2"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/infra/scanner/git"
	"github.com/ahrav/gitleaks-armada/internal/infra/scanner/url"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// SourceScanner defines a standardized interface for secret detection across different source types.
// It abstracts the scanning logic, allowing pluggable implementations for various data sources
// like Git repositories, URLs, and other potential scanning targets. Each implementation
// must handle source-specific nuances while providing a consistent scanning contract.
//
// The Scan method takes a context for cancellation and tracing, and a scan request
// containing metadata about the target. It returns an error to indicate scanning failures,
// allowing for granular error handling and observability.
type SourceScanner interface {
	Scan(ctx context.Context, task *dtos.ScanRequest) error
}

var (
	_ scanning.SecretScanner = (*Gitleaks)(nil)
	_ scanning.RuleProvider  = (*Gitleaks)(nil)
)

// Gitleaks provides secret scanning functionality by wrapping the Gitleaks detection engine.
// It handles scanning repositories for potential secrets and sensitive information leaks
// while providing observability through logging and tracing.
type Gitleaks struct {
	detector *detect.Detector
	logger   *logger.Logger
	tracer   trace.Tracer
	metrics  scanning.ScannerMetrics
}

// NewGitLeaks creates a new Gitleaks scanner instance with a configured detector.
// It initializes the scanning engine and publishes the default ruleset on startup to ensure
// consistent detection patterns across scanner instances. The scanner uses OpenTelemetry
// for tracing and structured logging for observability.
func NewGitLeaks(
	ctx context.Context,
	broker events.DomainEventPublisher,
	logger *logger.Logger,
	tracer trace.Tracer,
	metrics scanning.ScannerMetrics,
) *Gitleaks {
	detector := setupGitleaksDetector()
	// if err := publishRulesOnStartup(ctx, broker, detector, logger, tracer); err != nil {
	// 	logger.Error(ctx, "failed to publish rules on startup", "error", err)
	// }

	return &Gitleaks{
		detector: detector,
		logger:   logger,
		tracer:   tracer,
		metrics:  metrics,
	}
}

// GetRules implements the scanning.RuleProvider interface by streaming converted rules
// through a channel. It processes each rule from the Gitleaks detector and converts
// them to our domain model before sending.
func (s *Gitleaks) GetRules(ctx context.Context) (<-chan rules.GitleaksRuleMessage, error) {
	ctx, span := s.tracer.Start(ctx, "gitleaks_scanner.get_rules")
	defer span.End()

	ruleChan := make(chan rules.GitleaksRuleMessage, 1)

	go func() {
		defer close(ruleChan)

		for _, rule := range s.detector.Config.Rules {
			select {
			case <-ctx.Done():
				span.SetStatus(codes.Error, "context cancelled")
				span.RecordError(ctx.Err())
				s.logger.Warn(ctx, "Context cancelled while streaming rules")
				return
			default:
			}

			domainRule := convertDetectorRuleToRule(rule)
			msg := rules.GitleaksRuleMessage{
				GitleaksRule: domainRule,
				Hash:         domainRule.GenerateHash(),
			}

			select {
			case <-ctx.Done():
				span.SetStatus(codes.Error, "context cancelled")
				span.RecordError(ctx.Err())
				s.logger.Warn(ctx, "Context cancelled while streaming rules")
				return
			case ruleChan <- msg:
				span.AddEvent("rule_streamed", trace.WithAttributes(
					attribute.String("rule_id", rule.RuleID),
					attribute.String("hash", msg.Hash),
				))
			}
		}

		span.AddEvent("rules_streamed", trace.WithAttributes(
			attribute.Int("rule_count", len(s.detector.Config.Rules)),
		))
		span.SetStatus(codes.Ok, "rules streamed")
	}()

	span.AddEvent("rule_streaming_started", trace.WithAttributes(
		attribute.Int("total_rules", len(s.detector.Config.Rules)),
	))
	return ruleChan, nil
}

func convertDetectorRuleToRule(rule config.Rule) rules.GitleaksRule {
	return rules.GitleaksRule{
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
}

// Scan clones the repository to a temporary directory and scans it for secrets.
// It ensures the cloned repository is cleaned up after scanning.
func (s *Gitleaks) Scan(ctx context.Context, task *dtos.ScanRequest) error {
	ctx, span := s.tracer.Start(ctx, "gitleaks_scanner.scanning.scan_repository",
		trace.WithAttributes(
			attribute.String("task.id", task.TaskID.String()),
			attribute.String("source.type", string(task.SourceType)),
		))
	defer span.End()

	var scanner SourceScanner
	switch task.SourceType {
	case dtos.SourceTypeGitHub:
		scanner = git.NewScanner(s.detector, s.logger, s.tracer, s.metrics)
	case dtos.SourceTypeURL:
		scanner = url.NewScanner(s.detector, s.logger, s.tracer, s.metrics)
	default:
		return fmt.Errorf("unsupported source type: %s", task.SourceType)
	}

	return scanner.Scan(ctx, task)
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
