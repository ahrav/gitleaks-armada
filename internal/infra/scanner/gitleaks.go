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
	"github.com/ahrav/gitleaks-armada/internal/infra/scanner/sources/git"
	"github.com/ahrav/gitleaks-armada/internal/infra/scanner/sources/url"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

var (
	_ scanning.SecretScanner = (*Gitleaks)(nil)
	_ scanning.RuleProvider  = (*Gitleaks)(nil)
)

// Gitleaks provides secret scanning functionality by wrapping the Gitleaks detection engine.
// It handles scanning repositories for potential secrets and sensitive information leaks
// while providing observability through logging and tracing.
type Gitleaks struct {
	detector *detect.Detector

	// scannerFactories is a map of source type to scanner factory.
	// It is used to create scanners for different source types at runtime.
	scannerFactories map[dtos.SourceType]SourceScannerFactory

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics scanning.ScannerMetrics
}

// NewGitLeaks creates a new Gitleaks scanner instance with a configured detector.
// It initializes the scanning engine and publishes the default ruleset on startup to ensure
// consistent detection patterns across scanner instances. The scanner uses OpenTelemetry
// for tracing and structured logging for observability.
func NewGitLeaks(
	ctx context.Context,
	broker events.DomainEventPublisher,
	log *logger.Logger,
	tracer trace.Tracer,
	metrics scanning.ScannerMetrics,
) (*Gitleaks, error) {
	logger := log.With("component", "gitleaks_scanner")
	detector, err := setupGitleaksDetector()
	if err != nil {
		return nil, err
	}

	factories := map[dtos.SourceType]SourceScannerFactory{
		dtos.SourceTypeGitHub: func(params scannerParams) StreamScanner {
			return git.NewScanner(params.detector, params.logger, params.tracer, params.metrics)
		},
		dtos.SourceTypeURL: func(params scannerParams) StreamScanner {
			return url.NewScanner(params.detector, params.logger, params.tracer, params.metrics)
		},
	}

	return &Gitleaks{
		detector:         detector,
		scannerFactories: factories,
		logger:           logger,
		tracer:           tracer,
		metrics:          metrics,
	}, nil
}

// setupGitleaksDetector initializes the Gitleaks detector using the embedded default configuration.
func setupGitleaksDetector() (*detect.Detector, error) {
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(bytes.NewBufferString(config.DefaultConfig)); err != nil {
		return nil, fmt.Errorf("failed to read embedded config: %w", err)
	}

	var vc config.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal embedded config: %w", err)
	}

	cfg, err := vc.Translate()
	if err != nil {
		return nil, fmt.Errorf("failed to translate ViperConfig to Config: %w", err)
	}

	return detect.NewDetector(cfg), nil
}

// GetRules implements the scanning.RuleProvider interface by streaming converted rules
// through a channel. It processes each rule from the Gitleaks detector and converts
// them to our domain model before sending.
func (s *Gitleaks) GetRules(ctx context.Context) (<-chan rules.GitleaksRuleMessage, error) {
	ctx, span := s.tracer.Start(ctx, "gitleaks_scanner.scanning.get_rules",
		trace.WithAttributes(
			attribute.String("component", "gitleaks_scanner"),
			attribute.Int("num_rules", len(s.detector.Config.Rules)),
		),
	)
	defer span.End()

	ruleChan := make(chan rules.GitleaksRuleMessage, 1)

	go func() {
		defer close(ruleChan)

		for _, rule := range s.detector.Config.Rules {
			select {
			case <-ctx.Done():
				span.SetStatus(codes.Error, "context cancelled")
				span.RecordError(ctx.Err())
				s.logger.Warn(ctx, "GitleaksScanner: Context cancelled while streaming rules")
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
				s.logger.Warn(ctx, "GitleaksScanner: Context cancelled while streaming rules")
				return
			case ruleChan <- msg:
				span.AddEvent("rule_streamed", trace.WithAttributes(
					attribute.String("rule_id", rule.RuleID),
					attribute.String("hash", msg.Hash),
				))
			}
		}

		span.AddEvent("rules_streamed")
		span.SetStatus(codes.Ok, "rules streamed")
	}()

	span.AddEvent("rule_streaming_started")
	s.logger.Info(ctx, "Rules streaming started")

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

// StreamScanner defines a standardized interface for secret detection across different source types.
// It abstracts the scanning logic, allowing pluggable implementations for various data sources
// like Git repositories, URLs, and other potential scanning targets. Each implementation
// must handle source-specific nuances while providing a consistent scanning contract.
//
// The ScanStreaming method returns three channels:
//   - heartbeats: receives a signal (struct{}) on a fixed interval to indicate "still scanning"
//   - findings: streams discovered results
//   - errs: emits an error if the scan fails, or is closed on success
//
// The ScanStreaming method accepts a task and a progress reporter to allow for progress reporting.
type StreamScanner interface {
	// ScanStreaming returns three channels:
	//   - heartbeats: receives a signal (struct{}) on a fixed interval to indicate "still scanning"
	//   - findings: streams discovered results
	//   - errs: emits an error if the scan fails, or is closed on success
	ScanStreaming(ctx context.Context, task *dtos.ScanRequest, reporter scanning.ProgressReporter) (
		<-chan struct{}, // heartbeats
		<-chan scanning.Finding,
		<-chan error,
	)
}

// scannerParams collects all the dependencies needed to construct a SourceScanner.
type scannerParams struct {
	detector *detect.Detector
	logger   *logger.Logger
	tracer   trace.Tracer
	metrics  scanning.ScannerMetrics
}

// SourceScannerFactory is a function that constructs a SourceScanner.
type SourceScannerFactory func(params scannerParams) StreamScanner

// Scan initiates the scanning process for a given task by selecting the appropriate scanner
// based on the task's source type.
func (s *Gitleaks) Scan(ctx context.Context, task *dtos.ScanRequest, reporter scanning.ProgressReporter) scanning.StreamResult {
	logger := s.logger.With(
		"task.id", task.TaskID.String(),
		"source.type", task.SourceType,
		"source.uri", task.ResourceURI,
	)
	ctx, span := s.tracer.Start(ctx, "gitleaks_scanner.scanning.scan",
		trace.WithAttributes(
			attribute.String("component", "gitleaks_scanner"),
			attribute.String("task.id", task.TaskID.String()),
			attribute.String("source.type", string(task.SourceType)),
			attribute.String("source.uri", task.ResourceURI),
		),
	)
	defer span.End()

	scannerFactory, ok := s.scannerFactories[task.SourceType]
	if !ok {
		span.SetStatus(codes.Error, "unsupported source type")
		span.RecordError(fmt.Errorf("unsupported source type: %s", task.SourceType))
		errChan := make(chan error, 1)
		errChan <- fmt.Errorf("unsupported source type: %s", task.SourceType)
		return scanning.StreamResult{ErrChan: errChan}
	}
	span.AddEvent("scanner_factory_selected")

	scanner := scannerFactory(scannerParams{
		detector: s.detector,
		logger:   s.logger,
		tracer:   s.tracer,
		metrics:  s.metrics,
	})

	hbChan, findingsChan, errChan := scanner.ScanStreaming(ctx, task, reporter)

	// Return the channels in our StreamResult.
	sr := scanning.StreamResult{
		HeartbeatChan: hbChan,
		FindingsChan:  findingsChan,
		ErrChan:       errChan,
	}
	span.SetStatus(codes.Ok, "scan started streaming")
	span.AddEvent("scan_started_streaming")
	logger.Info(ctx, "Scan started streaming")

	return sr
}
