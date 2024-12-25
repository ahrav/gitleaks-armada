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

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
)

type GitLeaksScanner struct{ detector *detect.Detector }

// NewGitLeaksScanner constructs and returns a GitLeaksScanner instance with the detector set up.
func NewGitLeaksScanner(ctx context.Context, broker messaging.Broker) *GitLeaksScanner {
	detector := setupGitleaksDetector()
	if err := publishRulesOnStartup(ctx, broker, detector); err != nil {
		log.Fatalf("failed to publish rules on startup: %v", err)
	}

	return &GitLeaksScanner{detector: detector}
}

// Scan clones the repository to a temporary directory and scans it for secrets.
// It ensures the cloned repository is cleaned up after scanning.
func (s *GitLeaksScanner) Scan(ctx context.Context, repoURL string) error {
	tempDir, err := os.MkdirTemp("", "gitleaks-scan-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			log.Printf("failed to cleanup temp directory %s: %v", tempDir, err)
		}
	}()

	if err := cloneRepo(ctx, repoURL, tempDir); err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	gitCmd, err := sources.NewGitLogCmd(tempDir, "")
	if err != nil {
		return fmt.Errorf("failed to create git log command: %w", err)
	}

	findings, err := s.detector.DetectGit(gitCmd)
	if err != nil {
		return fmt.Errorf("failed to scan repository: %w", err)
	}

	log.Printf("found %d findings in repository %s", len(findings), repoURL)
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

func publishRulesOnStartup(ctx context.Context, broker messaging.Broker, detector *detect.Detector) error {
	return broker.PublishRules(ctx, ConvertDetectorConfigToDomain(detector.Config.Rules))
}

// ConvertDetectorConfigToDomain converts your Gitleaks config.Rules (compiled regex)
// into the domain-friendly GitleaksRuleSet (string-based).
func ConvertDetectorConfigToDomain(rules map[string]config.Rule) messaging.GitleaksRuleSet {
	var domainRules []messaging.GitleaksRule
	for _, gRule := range rules {
		dRule := messaging.GitleaksRule{
			RuleID:      gRule.RuleID,
			Description: gRule.Description,
			Entropy:     gRule.Entropy,
			SecretGroup: gRule.SecretGroup,
			Regex:       regexToString(gRule.Regex), // <--- convert *regexp.Regexp -> string
			Path:        regexToString(gRule.Path),  // same for path
			Tags:        gRule.Tags,
			Keywords:    gRule.Keywords,
			Allowlists:  convertAllowlists(gRule.Allowlists),
		}
		domainRules = append(domainRules, dRule)
	}

	return messaging.GitleaksRuleSet{
		Rules: domainRules,
	}
}

// regexToString safely gets the string pattern from a *regexp.Regexp
func regexToString(re *regexp.Regexp) string {
	if re == nil {
		return ""
	}
	return re.String()
}

// convertAllowlists maps []config.Allowlist -> []messaging.GitleaksAllowlist
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

// regexSliceToStrings converts []*regexp.Regexp -> []string
func regexSliceToStrings(res []*regexp.Regexp) []string {
	var out []string
	for _, re := range res {
		if re != nil {
			out = append(out, re.String())
		}
	}
	return out
}

// matchConditionToDomain maps config.AllowlistMatchCondition -> messaging.AllowlistMatchCondition
func matchConditionToDomain(mc config.AllowlistMatchCondition) messaging.AllowlistMatchCondition {
	switch mc {
	case config.AllowlistMatchOr:
		return messaging.MatchConditionOR
	case config.AllowlistMatchAnd:
		return messaging.MatchConditionAND
	default:
		// Not recognized or future extension
		return messaging.MatchConditionUnspecified
	}
}

// checkError logs the error and exits if the error is not nil.
func checkError(msg string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}
