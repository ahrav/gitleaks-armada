package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// metrics defines metrics operations for Git repository operations
type metrics interface {
	// ObserveScanDuration records how long it took to scan a repository.
	ObserveScanDuration(ctx context.Context, sourceType shared.SourceType, duration time.Duration)

	// ObserveScanSize records the size of a repository in bytes.
	ObserveScanSize(ctx context.Context, sourceType shared.SourceType, sizeBytes int64)

	// ObserveScanFindings records the number of findings in a repository.
	ObserveScanFindings(ctx context.Context, sourceType shared.SourceType, count int)

	// IncScanError increments the scan error counter for a repository.
	IncScanError(ctx context.Context, sourceType shared.SourceType)
}

// Scanner implements SecretScanner for git-based sources.
type Scanner struct {
	detector *detect.Detector
	logger   *logger.Logger
	tracer   trace.Tracer
	metrics  metrics
}

// NewScanner creates a new Git scanner instance.
func NewScanner(detector *detect.Detector, logger *logger.Logger, tracer trace.Tracer, metrics metrics) *Scanner {
	return &Scanner{
		detector: detector,
		logger:   logger,
		tracer:   tracer,
		metrics:  metrics,
	}
}

// Scan clones the repository to a temporary directory and scans it for secrets.
// It ensures the cloned repository is cleaned up after scanning.
func (s *Scanner) Scan(ctx context.Context, task *dtos.ScanRequest) error {
	ctx, span := s.tracer.Start(ctx, "gitleaks_scanner.scanning.scan_repository",
		trace.WithAttributes(
			attribute.String("repository.url", task.ResourceURI),
		))
	startTime := time.Now()
	defer func() {
		span.End()
		s.metrics.ObserveScanDuration(ctx, shared.SourceType(task.SourceType), time.Since(startTime))
	}()

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
		cleanupSpan := trace.SpanFromContext(ctx)
		defer cleanupSpan.End()
		cleanupSpan.AddEvent("starting_temp_dir_cleanup")
		if err := os.RemoveAll(tempDir); err != nil {
			cleanupSpan.RecordError(err)
			cleanupSpan.AddEvent("cleanup_failed")
			s.logger.Error(ctx, "failed to cleanup temp directory", "error", err)
			return
		}
		cleanupSpan.AddEvent("cleanup_successful")
	}()

	cloneSpan := trace.SpanFromContext(ctx)
	cloneSpan.AddEvent("starting_clone_repository")
	defer cloneSpan.End()

	startTime = time.Now()
	if err := cloneRepo(ctx, task.ResourceURI, tempDir); err != nil {
		cloneSpan.RecordError(err)
		cloneSpan.AddEvent("clone_failed")
		s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
		return fmt.Errorf("failed to clone repository: %w", err)
	}
	s.metrics.ObserveScanDuration(ctx, shared.SourceType(task.SourceType), time.Since(startTime))

	go s.calculateRepoSize(ctx, task, tempDir) // async repo size calculation

	cloneSpan.AddEvent("clone_successful")

	cmdSpan := trace.SpanFromContext(ctx)
	cmdSpan.AddEvent("starting_git_log_setup")
	gitCmd, err := sources.NewGitLogCmd(tempDir, "")
	if err != nil {
		cmdSpan.RecordError(err)
		cmdSpan.AddEvent("git_log_setup_failed")
		return fmt.Errorf("failed to create git log command: %w", err)
	}
	cmdSpan.AddEvent("git_log_setup_successful")

	_, detectSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.detect_secrets")
	defer detectSpan.End()

	detectSpan.AddEvent("starting_secret_detection")
	findings, err := s.detector.DetectGit(gitCmd)
	if err != nil {
		detectSpan.RecordError(err)
		detectSpan.AddEvent("secret_detection_failed")
		return fmt.Errorf("failed to scan repository: %w", err)
	}
	s.metrics.ObserveScanFindings(ctx, shared.SourceType(task.SourceType), len(findings))

	detectSpan.SetAttributes(
		attribute.Int("findings.count", len(findings)),
	)
	detectSpan.AddEvent("secret_detection_completed", trace.WithAttributes(
		attribute.Int("findings.count", len(findings)),
	))

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

// calculateRepoSize calculates the size of a repository asynchronously.
func (s *Scanner) calculateRepoSize(ctx context.Context, task *dtos.ScanRequest, tempDir string) {
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
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			sizeSpan.RecordError(err)
			s.logger.Warn(sizeCtx, "Failed to get repository size",
				"error", err,
				"repo", task.ResourceURI)
		}
		return
	}

	s.metrics.ObserveScanSize(sizeCtx, shared.SourceType(task.SourceType), size)
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
