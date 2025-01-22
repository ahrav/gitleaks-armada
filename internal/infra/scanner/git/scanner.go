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

	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Scanner implements SecretScanner for git-based sources.
type Scanner struct {
	detector *detect.Detector
	logger   *logger.Logger
	tracer   trace.Tracer
	metrics  scanning.SourceScanMetrics
}

// NewScanner creates a new Git scanner instance.
func NewScanner(
	detector *detect.Detector,
	logger *logger.Logger,
	tracer trace.Tracer,
	metrics scanning.SourceScanMetrics,
) *Scanner {
	return &Scanner{
		detector: detector,
		logger:   logger,
		tracer:   tracer,
		metrics:  metrics,
	}
}

// ScanStreaming performs asynchronous secret scanning on a git repository and streams results.
// It provides real-time feedback through three channels:
//   - A heartbeat channel to indicate the scanner is still alive
//   - A findings channel that emits discovered secrets
//   - An error channel for reporting scanning failures
//
// The scan continues until either the context is cancelled, an error occurs, or scanning completes.
// The caller should consume from all channels until they are closed to prevent goroutine leaks.
// TODO: Implement progress reporting.
func (s *Scanner) ScanStreaming(
	ctx context.Context,
	task *dtos.ScanRequest,
	reporter scanning.ProgressReporter,
) (<-chan struct{}, <-chan scanning.Finding, <-chan error) {
	heartbeatChan := make(chan struct{}, 1)
	findingsChan := make(chan scanning.Finding, 1)
	errChan := make(chan error, 1)

	go func() {
		defer close(heartbeatChan)
		defer close(findingsChan)
		defer close(errChan)

		ctx, span := s.tracer.Start(ctx, "gitleaks_scanner.scanning.scan_repository",
			trace.WithAttributes(
				attribute.String("repository.url", task.ResourceURI),
			))
		startTime := time.Now()
		defer func() {
			span.End()
			s.metrics.ObserveScanDuration(ctx, shared.SourceType(task.SourceType), time.Since(startTime))
		}()

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		scanComplete := make(chan error, 1)
		go func() {
			defer close(scanComplete)

			_, dirSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.create_temp_dir")
			tempDir, err := os.MkdirTemp("", "gitleaks-scan-")
			if err != nil {
				dirSpan.RecordError(err)
				dirSpan.End()
				span.AddEvent("temp_dir_creation_failed")
				scanComplete <- fmt.Errorf("failed to create temp directory: %w", err)
				return
			}
			dirSpan.End()
			span.AddEvent("temp_dir_created", trace.WithAttributes(
				attribute.String("temp_dir", tempDir),
			))

			// Ensure cleanup.
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

			startTime := time.Now()
			if err := cloneRepo(ctx, task.ResourceURI, tempDir); err != nil {
				cloneSpan.RecordError(err)
				cloneSpan.AddEvent("clone_failed")
				s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
				scanComplete <- fmt.Errorf("failed to clone repository: %w", err)
				return
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
				scanComplete <- fmt.Errorf("failed to create git log command: %w", err)
				return
			}
			cmdSpan.AddEvent("git_log_setup_successful")

			_, detectSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.detect_secrets")
			defer detectSpan.End()

			detectSpan.AddEvent("starting_secret_detection")
			findings, err := s.detector.DetectGit(gitCmd)
			if err != nil {
				detectSpan.RecordError(err)
				detectSpan.AddEvent("secret_detection_failed")
				scanComplete <- fmt.Errorf("failed to scan repository: %w", err)
				return
			}

			for _, finding := range findings {
				_ = finding // TODO: Convert to our domain's representation.
				select {
				case findingsChan <- scanning.Finding{}:
				case <-ctx.Done():
					return
				}
			}

			s.metrics.ObserveScanFindings(ctx, shared.SourceType(task.SourceType), len(findings))

			detectSpan.SetAttributes(
				attribute.Int("findings.count", len(findings)),
			)
			detectSpan.AddEvent("secret_detection_completed", trace.WithAttributes(
				attribute.Int("findings.count", len(findings)),
			))

			s.logger.Info(ctx, "found findings in repository",
				"repo_url", task.ResourceURI,
				"num_findings", len(findings))
			span.AddEvent("scan_completed", trace.WithAttributes(
				attribute.Int("findings.count", len(findings)),
			))

			scanComplete <- nil
		}()

		// Handle events.
		for {
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			case <-ticker.C:
				select {
				case heartbeatChan <- struct{}{}:
				default:
				}
			case err := <-scanComplete:
				if err != nil {
					errChan <- err
				}
				return
			}
		}
	}()

	return heartbeatChan, findingsChan, errChan
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
