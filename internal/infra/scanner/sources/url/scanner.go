package url

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/nlnwa/gowarc/v2"
	"github.com/zricethezav/gitleaks/v8/detect"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	srcs "github.com/ahrav/gitleaks-armada/internal/infra/scanner/sources"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Scanner is an implementation of SecretScanner for URL-based sources.
// It delegates concurrency (channels, heartbeats, etc.) to the shared ScanTemplate
// and focuses on how to fetch and process remote data.
type Scanner struct {
	scannerID string

	template *srcs.ScanTemplate
	detector *detect.Detector

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics scanning.SourceScanMetrics
}

// NewScanner creates a new scanner with the provided tracer, logger, metrics, and Gitleaks detector.
// We also initialize a shared ScanTemplate to handle concurrency and top-level spans.
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

// ScanStreaming sets up the concurrency flow via the ScanTemplate and then calls runURLScan
// for the actual logic. The returned channels convey heartbeats, findings, and errors.
// TODO: Implement progress reporting.
func (s *Scanner) ScanStreaming(
	ctx context.Context,
	scanReq *dtos.ScanRequest,
	reporter scanning.ProgressReporter,
) (<-chan struct{}, <-chan scanning.Finding, <-chan error) {
	scanCtx := NewScanContext(
		s.scannerID,
		scanReq.TaskID,
		scanReq.JobID,
		0,               // resumeFileIdx
		&atomic.Int64{}, // resumeSequence
		scanReq.Metadata["archive_format"],
		reporter,
		s.tracer,
	)

	opts := srcs.TemplateOptions{
		OperationName: "gitleaks_url_scanner.scan",
		OperationAttributes: []attribute.KeyValue{
			attribute.String("scanner_id", s.scannerID),
			attribute.String("url", scanReq.ResourceURI),
		},
		HeartbeatInterval: 5 * time.Second,
		OnPause: func(ctx context.Context, req *dtos.ScanRequest) {
			if err := scanCtx.HandlePause(ctx); err != nil {
				s.logger.Error(ctx, "Failed to handle scan pause",
					"error", err,
					"task_id", req.TaskID,
				)
				return
			}
			s.logger.Info(ctx, "Scan paused", "task_id", req.TaskID, "job_id", req.JobID)
		},
	}

	return s.template.ScanStreaming(ctx, scanReq, opts, reporter, func(ctx context.Context, task *dtos.ScanRequest, findingsChan chan<- scanning.Finding, reporter scanning.ProgressReporter) error {
		return s.runURLScan(ctx, task, findingsChan, scanCtx)
	})
}

// runURLScan encapsulates the main scanning logic, including fetching data
// via HTTP and optionally extracting archives before scanning them with Gitleaks.
func (s *Scanner) runURLScan(
	ctx context.Context,
	scanReq *dtos.ScanRequest,
	findingsChan chan<- scanning.Finding,
	scanCtx *ScanContext,
) error {
	logr := logger.NewLoggerContext(s.logger.With(
		"operation", "gitleaks_url_scanner.scan_main",
		"scanner_id", s.scannerID,
		"url", scanReq.ResourceURI,
		"source_type", scanReq.SourceType.String(),
		"task_id", scanReq.TaskID.String(),
		"job_id", scanReq.JobID.String(),
	))
	ctx, span := s.tracer.Start(ctx, "gitleaks_url_scanner.scan_main",
		trace.WithAttributes(
			attribute.String("scanner_id", s.scannerID),
			attribute.String("url", scanReq.ResourceURI),
			attribute.String("source_type", scanReq.SourceType.String()),
			attribute.String("task_id", scanReq.TaskID.String()),
			attribute.String("job_id", scanReq.JobID.String()),
		),
	)
	defer span.End()

	startTime := time.Now()
	defer func() {
		s.metrics.ObserveScanDuration(ctx, shared.ParseSourceType(scanReq.SourceType.String()), time.Since(startTime))
		span.SetAttributes(attribute.Int64("scan_duration_ms", time.Since(startTime).Milliseconds()))
	}()

	var sequenceNum atomic.Int64
	if seqStr, ok := scanReq.Metadata[dtos.MetadataKeySequenceNum]; ok {
		seqVal, err := strconv.ParseInt(seqStr, 10, 64)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "invalid sequence number format")
			return fmt.Errorf("invalid sequence number format (metadata: %s): %w", seqStr, err)
		}
		sequenceNum.Store(seqVal)
	}
	logr.Add("sequence_num", sequenceNum.Load())

	var resumeFileIdx int64
	format := "none"

	// Handle checkpoint data once if it exists.
	// TODO: This is absolutely horrendous, we need to fix this...
	if ckptStr, ok := scanReq.Metadata[dtos.MetadataKeyCheckpoint]; ok {
		var checkpoint domain.Checkpoint
		if err := checkpoint.UnmarshalJSON([]byte(ckptStr)); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "invalid checkpoint format")
			return fmt.Errorf("invalid checkpoint format: %w", err)
		}

		// Extract file index from checkpoint
		if fileIdx, ok := checkpoint.Metadata()["file_index"]; ok {
			idxVal, err := strconv.ParseInt(fileIdx, 10, 64)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "invalid file_index format")
				return fmt.Errorf("invalid file_index format: %w", err)
			}
			span.SetAttributes(attribute.Int64("resume_file_index", idxVal))
			resumeFileIdx = idxVal
			logr.Add("resume_file_index", resumeFileIdx)
			logr.Debug(ctx, "resuming scan from file index")
		}

		// Extract archive format from checkpoint.
		if formatStr, ok := checkpoint.Metadata()["archive_format"]; ok {
			format = formatStr
		}
	} else if formatStr, ok := scanReq.Metadata["archive_format"]; ok {
		// If no checkpoint, check direct metadata (enumeration case).
		format = formatStr
	}
	span.SetAttributes(attribute.String("archive_format", format))

	scanCtx.nextSequence.Store(sequenceNum.Load())

	// Prepare a specialized ArchiveReader based on format (e.g., "warc.gz")
	reader, err := s.createArchiveReader(ctx, format, scanReq, scanCtx, logr)
	if err != nil {
		s.metrics.IncScanError(ctx, shared.ParseSourceType(scanReq.SourceType.String()))
		return fmt.Errorf("failed to create archive reader with format %s and task resource URI %s: %w",
			format, scanReq.ResourceURI, err)
	}
	defer reader.Close()
	logr.Debug(ctx, "archive reader created")

	_, detectSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.detect_secrets")
	detectSpan.AddEvent("gitleaks_detection_started")

	logr.Info(ctx, "starting gitleaks detection for URL")
	// Gitleaks can read from an io.Reader. (the decompressed or raw data)
	findings, errs := s.detector.StreamDetectReader(reader, 32)

	for f := range findings {
		_ = f // TODO: Convert to our domain's representation.
		select {
		case findingsChan <- scanning.Finding{}:
		case <-ctx.Done():
			detectSpan.End()
			return ctx.Err()
		}
	}

	for e := range errs {
		s.metrics.IncScanError(ctx, shared.ParseSourceType(scanReq.SourceType.String()))
		detectSpan.RecordError(e)
		detectSpan.SetStatus(codes.Error, "gitleaks_detection_error")
	}

	s.metrics.ObserveScanFindings(ctx, shared.ParseSourceType(scanReq.SourceType.String()), len(findings))
	detectSpan.AddEvent("findings_processed",
		trace.WithAttributes(attribute.Int("findings.count", len(findings))))
	detectSpan.End()

	logr.Info(ctx, "URLScanner: found findings in URL-based data",
		"url", scanReq.ResourceURI,
		"num_findings", len(findings),
	)
	span.SetStatus(codes.Ok, "scan_completed")

	return nil
}

// ScanContext holds shared state for a single scanning operation.
// It can track the next sequence number, the progress reporter, and optional resume offsets.
type ScanContext struct {
	scannerID string

	taskID        uuid.UUID
	jobID         uuid.UUID
	reporter      scanning.ProgressReporter
	nextSequence  *atomic.Int64
	resumeFileIdx int64
	archiveFormat string

	tracer trace.Tracer

	// lastProgress tracks the most recent progress state
	lastProgress atomic.Value // stores domain.Progress
}

// NewScanContext constructs a ScanContext, typically called once at the start of a scan.
func NewScanContext(
	scannerID string,
	taskID uuid.UUID,
	jobID uuid.UUID,
	resumeFileIdx int64,
	resumeSequence *atomic.Int64,
	archiveFormat string,
	reporter scanning.ProgressReporter,
	tracer trace.Tracer,
) *ScanContext {
	sc := &ScanContext{
		scannerID:     scannerID,
		taskID:        taskID,
		jobID:         jobID,
		reporter:      reporter,
		nextSequence:  resumeSequence,
		resumeFileIdx: resumeFileIdx,
		archiveFormat: archiveFormat,
		tracer:        tracer,
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
func (sc *ScanContext) ReportProgress(ctx context.Context, itemsProcessed int64, message string) error {
	ctx, span := sc.tracer.Start(ctx, "gitleaks_url_scanner.report_progress",
		trace.WithAttributes(
			attribute.String("scanner_id", sc.scannerID),
			attribute.String("task_id", sc.taskID.String()),
			attribute.String("job_id", sc.jobID.String()),
			attribute.Int64("items_processed", itemsProcessed),
			attribute.String("message", message),
		),
	)
	defer span.End()

	seqNum := sc.NextSequence()

	span.SetAttributes(attribute.Int64("sequence_num", seqNum))

	// Create metadata map for the checkpoint.
	metadata := map[string]string{
		"file_index":     strconv.FormatInt(itemsProcessed, 10),
		"archive_format": sc.archiveFormat,
	}

	progress := domain.NewProgress(
		sc.taskID,
		sc.jobID,
		seqNum,
		time.Now(),
		itemsProcessed,
		0,
		message,
		nil,
		domain.NewCheckpoint(
			sc.taskID,
			[]byte(strconv.FormatInt(itemsProcessed, 10)),
			metadata,
		),
	)

	// Store the progress for potential pause/cancel scenarios.
	sc.lastProgress.Store(progress)

	return sc.reporter.ReportProgress(ctx, progress)
}

// HandlePause emits a TaskPausedEvent with the latest progress.
func (sc *ScanContext) HandlePause(ctx context.Context) error {
	ctx, span := sc.tracer.Start(ctx, "scan_context.handle_pause")
	defer span.End()

	lastProgress := sc.lastProgress.Load().(domain.Progress)
	newProgress := domain.NewProgress(
		sc.taskID,
		sc.jobID,
		sc.NextSequence(),
		time.Now(),
		lastProgress.ItemsProcessed(),
		0,
		"",
		nil,
		domain.NewCheckpoint(
			sc.taskID,
			[]byte(strconv.FormatInt(lastProgress.ItemsProcessed(), 10)),
			map[string]string{
				"file_index":     strconv.FormatInt(lastProgress.ItemsProcessed(), 10),
				"archive_format": sc.archiveFormat,
			},
		),
	)

	return sc.reporter.ReportPausedProgress(ctx, newProgress)
}

// createArchiveReader performs an HTTP GET and then wraps the response Body
// in an ArchiveReader if needed (e.g., WARC, gzipped).
func (s *Scanner) createArchiveReader(
	ctx context.Context,
	format string,
	task *dtos.ScanRequest,
	scanCtx *ScanContext,
	logr *logger.LoggerContext,
) (io.ReadCloser, error) {
	_, archiveSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.create_archive_reader")
	defer archiveSpan.End()

	logr.Info(ctx, "Creating archive reader", "format", format)

	archiveReader, err := newArchiveReader(
		s.scannerID,
		format,
		func(size int64) {
			s.metrics.ObserveScanSize(ctx, shared.ParseSourceType(string(task.SourceType)), size)
		},
		logr,
		s.tracer,
	)
	if err != nil {
		archiveSpan.RecordError(err)
		return nil, fmt.Errorf("failed to create archive reader: %w", err)
	}

	_, httpSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.http_request",
		trace.WithSpanKind(trace.SpanKindClient))
	defer httpSpan.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, task.ResourceURI, nil)
	if err != nil {
		httpSpan.RecordError(err)
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		httpSpan.RecordError(err)
		httpSpan.SetAttributes(attribute.String("error", err.Error()))
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	httpSpan.SetAttributes(
		attribute.Int("response_status_code", resp.StatusCode),
		attribute.String("response_status", resp.Status),
	)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		errMsg := fmt.Sprintf("non-2xx response code %d", resp.StatusCode)
		httpSpan.RecordError(errors.New(errMsg))
		return nil, fmt.Errorf("failed to fetch URL: %s", errMsg)
	}

	processCtx, processSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.process_archive")
	defer processSpan.End()

	reader, err := archiveReader.Read(processCtx, resp.Body, scanCtx)
	if err != nil {
		processSpan.RecordError(err)
		s.metrics.IncScanError(ctx, shared.ParseSourceType(string(task.SourceType)))
		return nil, fmt.Errorf("failed to process archive: %w", err)
	}

	// Wrap the reader in order to provide a mechanism to close the response body
	// when we are done streaming the contents of the response body.
	return newWrappedReadCloser(reader, resp.Body), nil
}

type readCloser struct {
	r io.Reader
	c io.Closer
}

// newWrappedReadCloser returns an io.ReadCloser that reads from reader
// but also closes the response body when .Close() is called.
// This is necessary because we are streaming the response body to Gitleaks
// and we want to close the response body when we are done.
func newWrappedReadCloser(reader io.Reader, body io.Closer) io.ReadCloser {
	return &readCloser{
		r: reader,
		c: body, // we want to close the response body
	}
}

// Read from the underlying reader.
func (rc *readCloser) Read(p []byte) (int, error) { return rc.r.Read(p) }

// Close the underlying reader and the response body.
func (rc *readCloser) Close() error { return rc.c.Close() }

// ArchiveReader is an interface for archive readers.
// It defines a method for reading from an input stream.
// It also takes a reporter for progress reporting.
type ArchiveReader interface {
	Read(ctx context.Context, input io.Reader, scanCtx *ScanContext) (io.Reader, error)
}

// newArchiveReader is a factory function that creates an appropriate reader based on the format string.
// It returns an ArchiveReader and an error.
func newArchiveReader(
	scannerID string,
	format string,
	sizeCallback func(int64),
	logger *logger.LoggerContext,
	tracer trace.Tracer,
) (ArchiveReader, error) {
	switch format {
	case "warc.gz":
		return newWarcGzReader(scannerID, sizeCallback, logger, tracer), nil
	case "none", "":
		return new(PassthroughReader), nil
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", format)
	}
}

// WarcGzReader is a struct that implements the ArchiveReader interface.
// It reads WARC.GZ files.
type WarcGzReader struct {
	scannerID string

	sizeCallback func(int64) // Callback to report final size
	logger       *logger.LoggerContext
	tracer       trace.Tracer
}

func newWarcGzReader(
	scannerID string,
	sizeCallback func(int64),
	logger *logger.LoggerContext,
	tracer trace.Tracer,
) *WarcGzReader {
	return &WarcGzReader{
		scannerID:    scannerID,
		sizeCallback: sizeCallback,
		logger:       logger,
		tracer:       tracer,
	}
}

// Read is a method of the WarcGzReader struct.
// It reads from an input stream and returns a reader and an error.
// TODO: Consider if reporting progress here is okay as opposed to after we've
// actually scanned it via the Gitleaks scanner.
func (w *WarcGzReader) Read(
	ctx context.Context,
	input io.Reader,
	scanCtx *ScanContext,
) (io.Reader, error) {
	ctx, readSpan := w.tracer.Start(ctx, "warc_reader.read")
	defer readSpan.End()

	w.logger.Debug(ctx, "Starting WarcGzReader.Read",
		"resume_file_idx", scanCtx.resumeFileIdx)

	warcReader, err := gowarc.NewWarcFileReaderFromStream(input, 0)
	if err != nil {
		readSpan.RecordError(err)
		w.logger.Error(ctx, "Failed to create WARC reader", "error", err)
		return nil, fmt.Errorf("failed to create WARC reader: %w", err)
	}
	w.logger.Debug(ctx, "Successfully created WARC reader")

	// Uses a pipe to concurrently process WARC records while streaming their contents.
	// This allows memory-efficient processing of large WARC files by reading and consuming
	// records simultaneously rather than loading the entire file into memory.
	pr, pw := io.Pipe()
	bw := bufio.NewWriter(pw)

	w.logger.Debug(ctx, "WarcGzReader: starting to read WARC records")

	go func() {
		var totalSize int64
		const batchSize = 1000 // Number of records to process before reporting progress
		var lastReportedCount int64
		// This helps us report progress on scans that are resumed from a checkpoint.
		firstProcessedRecord := false

		w.logger.Debug(ctx, "Starting WARC processing",
			"resume_file_idx", scanCtx.resumeFileIdx,
			"first_processed_record", firstProcessedRecord)

		defer func() {
			if w.sizeCallback != nil {
				w.sizeCallback(totalSize)
			}
			bw.Flush()
			pw.Close()
			warcReader.Close()
		}()

		var recordCount int64

		// Helper function to report progress.
		reportProgress := func(message string) {
			if err := scanCtx.ReportProgress(ctx, recordCount, message); err != nil {
				readSpan.RecordError(err)
				w.logger.Error(ctx, "failed to report progress", "error", err)
			}
			w.logger.Debug(ctx, "progress reported", "message", message, "record_count", recordCount)
			lastReportedCount = recordCount
		}

		for {
			if ctx.Err() != nil {
				readSpan.RecordError(ctx.Err())
				pw.CloseWithError(ctx.Err())
				w.logger.Error(ctx, "failed to read WARC records", "error", ctx.Err())
				return
			}

			record, _, _, err := warcReader.Next()
			if errors.Is(err, io.EOF) {
				// Report final progress if we haven't reported for this batch.
				if recordCount > lastReportedCount {
					reportProgress(fmt.Sprintf("Processed %d WARC records", recordCount))
				}
				return
			}
			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to read WARC record: %w", err))
				readSpan.RecordError(err)
				w.logger.Error(ctx, "failed to read WARC record", "error", err)
				return
			}

			if record.Type() != gowarc.Response {
				continue
			}
			recordCount++
			if recordCount < scanCtx.resumeFileIdx {
				continue
			}

			// Report progress on:
			// 1. First processed record (after resume point).
			// 2. Every batchSize records thereafter.
			if !firstProcessedRecord || recordCount%batchSize == 0 {
				reportProgress(fmt.Sprintf("Processing WARC record %d", recordCount))
				firstProcessedRecord = true
			}

			bodyReader, err := record.Block().RawBytes()
			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to get record body: %w", err))
				readSpan.RecordError(err)
				w.logger.Error(ctx, "failed to get record body", "error", err)
				return
			}

			size, err := io.Copy(bw, bodyReader)
			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to copy record body: %w", err))
				readSpan.RecordError(err)
				w.logger.Error(ctx, "failed to copy record body", "error", err)
				return
			}

			totalSize += size
		}
	}()

	return pr, nil
}

// PassthroughReader is a struct that implements the ArchiveReader interface.
// It is a simple passthrough reader for uncompressed content.
type PassthroughReader struct{}

// Read is a method of the PassthroughReader struct.
// It reads from an input stream and returns a reader and an error.
func (p *PassthroughReader) Read(
	ctx context.Context,
	input io.Reader,
	scanCtx *ScanContext,
) (io.Reader, error) {
	return input, nil
}
