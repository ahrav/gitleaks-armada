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

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	srcs "github.com/ahrav/gitleaks-armada/internal/infra/scanner/sources"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Scanner scans Git repositories, relying on ScanTemplate for concurrency,
// channel management, and top-level tracing.
// TODO: Update tracing and logging.
type Scanner struct {
	template *srcs.ScanTemplate
	detector *detect.Detector
	logger   *logger.Logger
	tracer   trace.Tracer
	metrics  scanning.SourceScanMetrics
}

// NewScanner wires up a Scanner with required resources and a shared ScanTemplate.
func NewScanner(
	detector *detect.Detector,
	logger *logger.Logger,
	tracer trace.Tracer,
	metrics scanning.SourceScanMetrics,
) *Scanner {
	return &Scanner{
		template: srcs.NewScanTemplate(tracer, logger, metrics),
		detector: detector,
		logger:   logger,
		tracer:   tracer,
		metrics:  metrics,
	}
}

// ScanStreaming invokes the shared ScanTemplate and delegates the actual Git scanning
// logic to runGitScan. It returns three channels for heartbeats, findings, and errors.
// TODO: Implement progress reporting.
func (s *Scanner) ScanStreaming(
	ctx context.Context,
	scanReq *dtos.ScanRequest,
	reporter scanning.ProgressReporter,
) (<-chan struct{}, <-chan scanning.Finding, <-chan error) {
	opts := srcs.TemplateOptions{
		OperationName: "git_scanner.scan",
		OperationAttributes: []attribute.KeyValue{
			attribute.String("repository_url", scanReq.ResourceURI),
		},
		HeartbeatInterval: 5 * time.Second,
	}
	return s.template.ScanStreaming(ctx, scanReq, opts, reporter, s.runGitScan)
}

// runGitScan performs the repository clone, invokes Gitleaks, and streams findings.
// Additional tracing spans record each step for observability.
func (s *Scanner) runGitScan(
	ctx context.Context,
	scanReq *dtos.ScanRequest,
	findingsChan chan<- scanning.Finding,
	reporter scanning.ProgressReporter,
) error {
	ctx, span := s.tracer.Start(ctx, "gitleaks_scanner.scanning.scan_repository",
		trace.WithAttributes(attribute.String("repository_url", scanReq.ResourceURI)))
	defer span.End()

	startTime := time.Now()
	defer func() {
		s.metrics.ObserveScanDuration(ctx, shared.ParseSourceType(string(scanReq.SourceType)), time.Since(startTime))
	}()

	tempDir, err := os.MkdirTemp("", "gitleaks-scan-")
	if err != nil {
		span.RecordError(err)
		span.AddEvent("temp_dir_creation_failed")
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	span.AddEvent("temp_dir_created", trace.WithAttributes(attribute.String("temp_dir", tempDir)))

	defer func() {
		ctx, cleanupSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.cleanup_temp_dir")
		defer cleanupSpan.End()

		if rmErr := os.RemoveAll(tempDir); rmErr != nil {
			cleanupSpan.RecordError(rmErr)
			cleanupSpan.AddEvent("cleanup_failed")
			s.logger.Error(ctx, "failed to remove temp directory", "error", rmErr)
		} else {
			cleanupSpan.AddEvent("cleanup_successful")
		}
	}()

	_, cloneSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.clone_repository")
	cloneSpan.AddEvent("starting_clone_repository")
	cloneStart := time.Now()
	if err := cloneRepo(ctx, scanReq.ResourceURI, tempDir); err != nil {
		cloneSpan.RecordError(err)
		cloneSpan.AddEvent("clone_failed")
		s.metrics.IncScanError(ctx, shared.ParseSourceType(string(scanReq.SourceType)))
		cloneSpan.End()
		return fmt.Errorf("failed to clone repository: %w", err)
	}
	s.metrics.ObserveScanDuration(ctx, shared.ParseSourceType(string(scanReq.SourceType)), time.Since(cloneStart))
	cloneSpan.AddEvent("clone_successful")
	cloneSpan.End()

	go s.calculateRepoSize(ctx, scanReq, tempDir)

	cmdSpan := trace.SpanFromContext(ctx)
	cmdSpan.AddEvent("starting_git_log_setup")
	gitCmd, err := sources.NewGitLogCmd(tempDir, "")
	if err != nil {
		cmdSpan.RecordError(err)
		cmdSpan.AddEvent("git_log_setup_failed")
		return fmt.Errorf("failed to create git log command: %w", err)
	}
	cmdSpan.AddEvent("git_log_setup_successful")

	ctx, detectSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.detect_secrets")
	detectSpan.AddEvent("starting_secret_detection")
	findings, err := s.detector.DetectGit(gitCmd, &detect.RemoteInfo{Platform: scm.NoPlatform})
	if err != nil {
		detectSpan.RecordError(err)
		detectSpan.AddEvent("secret_detection_failed")
		detectSpan.End()
		return fmt.Errorf("failed to scan repository: %w", err)
	}

	for _, f := range findings {
		_ = f // TODO: Convert to our domain's representation.
		select {
		case findingsChan <- scanning.Finding{}:
		case <-ctx.Done():
			detectSpan.End()
			return ctx.Err()
		}
	}

	s.metrics.ObserveScanFindings(ctx, shared.ParseSourceType(string(scanReq.SourceType)), len(findings))
	detectSpan.SetAttributes(attribute.Int("findings.count", len(findings)))
	detectSpan.AddEvent("secret_detection_completed",
		trace.WithAttributes(attribute.Int("findings_count", len(findings))))
	detectSpan.End()

	s.logger.Info(ctx, "found findings in repository",
		"repo_url", scanReq.ResourceURI,
		"num_findings", len(findings))

	span.AddEvent("scan_completed", trace.WithAttributes(
		attribute.Int("findings_count", len(findings)),
	))

	return nil
}

func cloneRepo(ctx context.Context, repoURL, dir string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", repoURL, dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w: %s", err, stderr.String())
	}
	return nil
}

func (s *Scanner) calculateRepoSize(ctx context.Context, scanReq *dtos.ScanRequest, tempDir string) {
	const defaultTimeout = 2 * time.Minute
	sizeCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	_, sizeSpan := s.tracer.Start(sizeCtx, "gitleaks_scanner.calculate_repo_size",
		trace.WithAttributes(
			attribute.String("repository_url", scanReq.ResourceURI),
			attribute.String("task_id", scanReq.TaskID.String()),
			attribute.String("clone_path", tempDir),
		))
	defer sizeSpan.End()

	size, err := getDirSize(sizeCtx, tempDir)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			sizeSpan.RecordError(err)
			s.logger.Warn(sizeCtx, "failed to get repository size",
				"error", err,
				"repo_url", scanReq.ResourceURI,
			)
		}
		return
	}

	s.metrics.ObserveScanSize(sizeCtx, shared.ParseSourceType(string(scanReq.SourceType)), size)
	sizeSpan.AddEvent("size_calculation_complete",
		trace.WithAttributes(attribute.Int64("size_bytes", size)))
}

func getDirSize(ctx context.Context, path string) (int64, error) {
	var size int64
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if !d.IsDir() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			size += fi.Size()
		}
		return nil
	})
	return size, err
}
