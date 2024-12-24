package scanner

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"
)

type GitLeaksScanner struct{ detector *detect.Detector }

// NewGitLeaksScanner constructs and returns a GitLeaksScanner instance with the detector set up.
func NewGitLeaksScanner() *GitLeaksScanner {
	return &GitLeaksScanner{detector: setupGitleaksDetector()}
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

// checkError logs the error and exits if the error is not nil.
func checkError(msg string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}
