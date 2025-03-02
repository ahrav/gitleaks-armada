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
	"sync/atomic"
	"time"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	srcs "github.com/ahrav/gitleaks-armada/internal/infra/scanner/sources"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// ScanContext maintains state throughout a Git scanning operation.
// It tracks progress information that can be used for pause and resume
// functionality, including the sequence number for ordered events.
type ScanContext struct {
	scannerID     string
	taskID        uuid.UUID
	jobID         uuid.UUID
	reporter      scanning.ProgressReporter
	nextSequence  *atomic.Int64
	tempDir       string // Path to cloned repository
	commitScanned int64  // Number of commits processed so far

	tracer trace.Tracer

	// lastProgress tracks the most recent progress state.
	lastProgress atomic.Value // stores domain.Progress
}

// NewScanContext constructs a ScanContext for Git scanning operations.
func NewScanContext(
	scannerID string,
	taskID uuid.UUID,
	jobID uuid.UUID,
	reporter scanning.ProgressReporter,
	tempDir string,
	tracer trace.Tracer,
) *ScanContext {
	sc := &ScanContext{
		scannerID:    scannerID,
		taskID:       taskID,
		jobID:        jobID,
		reporter:     reporter,
		nextSequence: &atomic.Int64{},
		tempDir:      tempDir,
		tracer:       tracer,
	}

	// Initialize with empty progress.
	sc.lastProgress.Store(domain.NewProgress(
		taskID,
		jobID,
		0,
		time.Now(),
		0,
		0,
		"",
		nil,
		nil,
	))
	return sc
}

// NextSequence increments and returns the next sequence number for progress events.
func (sc *ScanContext) NextSequence() int64 { return sc.nextSequence.Add(1) }

// ReportProgress emits a progress event with the current sequence number
// and any other relevant data.
func (sc *ScanContext) ReportProgress(ctx context.Context, commitsProcessed int64, message string) error {
	ctx, span := sc.tracer.Start(ctx, "git_scanner.report_progress",
		trace.WithAttributes(
			attribute.String("scanner_id", sc.scannerID),
			attribute.String("task_id", sc.taskID.String()),
			attribute.String("job_id", sc.jobID.String()),
			attribute.Int64("commits_processed", commitsProcessed),
			attribute.String("message", message),
		),
	)
	defer span.End()

	seqNum := sc.NextSequence()
	span.SetAttributes(attribute.Int64("sequence_num", seqNum))

	// Store commit count in checkpoint metadata.
	metadata := map[string]string{
		"commits_processed": fmt.Sprintf("%d", commitsProcessed),
		"temp_dir":          sc.tempDir,
	}

	progress := domain.NewProgress(
		sc.taskID,
		sc.jobID,
		seqNum,
		time.Now(),
		commitsProcessed,
		0,
		message,
		nil,
		domain.NewCheckpoint(
			sc.taskID,
			[]byte(fmt.Sprintf("%d", commitsProcessed)),
			metadata,
		),
	)

	// Store the progress for potential pause/cancel scenarios.
	sc.lastProgress.Store(progress)
	sc.commitScanned = commitsProcessed

	return sc.reporter.ReportProgress(ctx, progress)
}

// HandlePause emits a TaskPausedEvent with the latest progress.
func (sc *ScanContext) HandlePause(ctx context.Context) error {
	ctx, span := sc.tracer.Start(ctx, "git_scanner.handle_pause")
	defer span.End()

	lastProgress := sc.lastProgress.Load().(domain.Progress)
	newProgress := domain.NewProgress(
		sc.taskID,
		sc.jobID,
		sc.NextSequence(),
		time.Now(),
		lastProgress.ItemsProcessed(),
		0,
		"Scan paused",
		nil,
		domain.NewCheckpoint(
			sc.taskID,
			[]byte(fmt.Sprintf("%d", sc.commitScanned)),
			map[string]string{
				"commits_processed": fmt.Sprintf("%d", sc.commitScanned),
				"temp_dir":          sc.tempDir,
			},
		),
	)

	return sc.reporter.ReportPausedProgress(ctx, newProgress)
}

// Scanner scans Git repositories, relying on ScanTemplate for concurrency,
// channel management, and top-level tracing.
// TODO: Update tracing and logging.
type Scanner struct {
	scannerID string
	template  *srcs.ScanTemplate
	detector  *detect.Detector
	logger    *logger.Logger
	tracer    trace.Tracer
	metrics   scanning.SourceScanMetrics
}

// NewScanner wires up a Scanner with required resources and a shared ScanTemplate.
func NewScanner(
	scannerID string,
	detector *detect.Detector,
	logger *logger.Logger,
	tracer trace.Tracer,
	metrics scanning.SourceScanMetrics,
) *Scanner {
	return &Scanner{
		scannerID: scannerID,
		template:  srcs.NewScanTemplate(tracer, logger, metrics),
		detector:  detector,
		logger:    logger,
		tracer:    tracer,
		metrics:   metrics,
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
			attribute.String("scanner_id", s.scannerID),
			attribute.String("repository_url", scanReq.ResourceURI),
		},
		HeartbeatInterval: 5 * time.Second,
		// TODO: Change this once we use a streaming variant of DetectGit.
		OnPause: func(ctx context.Context, req *dtos.ScanRequest) {
			// The scan context is created in runGitScan, but we don't have access to it here.
			// So we'll log a message indicating that we need to rely on the most recent
			// progress update that was reported before the pause.
			s.logger.Info(ctx, "Scan paused, using most recent progress update for resume state",
				"task_id", req.TaskID,
				"job_id", req.JobID,
			)
			// Note: The actual pause handling happens in runGitScan via context cancellation
		},
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
		trace.WithAttributes(
			attribute.String("scanner_id", s.scannerID),
			attribute.String("repository_url", scanReq.ResourceURI),
		))
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

	// Create a scan context to track progress
	scanCtx := NewScanContext(
		s.scannerID,
		scanReq.TaskID,
		scanReq.JobID,
		reporter,
		tempDir,
		s.tracer,
	)

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

	// Report initial progress after successful clone
	if err := scanCtx.ReportProgress(ctx, 0, "Repository cloned successfully, starting scan"); err != nil {
		s.logger.Warn(ctx, "Failed to report initial progress", "error", err)
	}

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

	// Setup a goroutine to handle pause events.
	pauseCh := make(chan struct{})
	go func() {
		for range ctx.Done() {
			if cause := context.Cause(ctx); cause == scanning.PauseEvent {
				s.logger.Info(ctx, "Handling pause event",
					"task_id", scanReq.TaskID,
					"job_id", scanReq.JobID,
				)
				pauseCh <- struct{}{}

				// Handle pause with the latest progress.
				if err := scanCtx.HandlePause(context.Background()); err != nil {
					s.logger.Error(context.Background(), "Failed to handle scan pause",
						"error", err,
						"task_id", scanReq.TaskID,
					)
				}
			}
		}
	}()

	// Start a progress reporting goroutine.
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		commitCount := atomic.Int64{}
		// Send initial progress report.
		if err := scanCtx.ReportProgress(ctx, 0, "Repository cloned successfully, starting scan"); err != nil {
			s.logger.Warn(ctx, "Failed to report initial progress", "error", err)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-pauseCh:
				return
			case <-progressDone:
				// Report progress one last time.
				count := commitCount.Load()
				if err := scanCtx.ReportProgress(ctx, count, fmt.Sprintf("Processed %d commits so far", count)); err != nil {
					s.logger.Warn(ctx, "Failed to report progress", "error", err)
				}
				return
			case <-ticker.C:
				count := commitCount.Load()
				if err := scanCtx.ReportProgress(ctx, count, fmt.Sprintf("Processed %d commits so far", count)); err != nil {
					s.logger.Warn(ctx, "Failed to report progress", "error", err)
				}
			}
		}
	}()

	scanCtx.commitScanned = 0

	ctx, detectSpan := s.tracer.Start(ctx, "gitleaks_scanner.scanning.detect_secrets")
	detectSpan.AddEvent("starting_secret_detection")
	findings, err := s.detector.DetectGit(gitCmd, &detect.RemoteInfo{Platform: scm.NoPlatform})

	// Signal to progress reporter that we're done.
	progressDone <- struct{}{}

	if err != nil && !errors.Is(err, context.Canceled) {
		detectSpan.RecordError(err)
		detectSpan.AddEvent("secret_detection_failed")
		detectSpan.End()
		return fmt.Errorf("failed to scan repository: %w", err)
	}

	// Count the findings and send them to the channel.
	foundCount := 0
	for _, f := range findings {
		_ = f // TODO: Convert to our domain's representation.
		scanCtx.commitScanned++
		foundCount++
		select {
		case findingsChan <- scanning.Finding{}:
		case <-ctx.Done():
			detectSpan.End()
			return ctx.Err()
		}
	}

	s.metrics.ObserveScanFindings(ctx, shared.ParseSourceType(string(scanReq.SourceType)), foundCount)
	detectSpan.SetAttributes(attribute.Int("findings.count", foundCount))
	detectSpan.AddEvent("secret_detection_completed",
		trace.WithAttributes(attribute.Int("findings_count", foundCount)))
	detectSpan.End()

	s.logger.Info(ctx, "found findings in repository",
		"repo_url", scanReq.ResourceURI,
		"num_findings", foundCount)

	span.AddEvent("scan_completed", trace.WithAttributes(
		attribute.Int("findings_count", foundCount),
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
			attribute.String("scanner_id", s.scannerID),
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
