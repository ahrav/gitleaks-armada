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

	"github.com/google/uuid"
	"github.com/nlnwa/gowarc"
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
)

// Scanner is an implementation of SecretScanner for URL-based sources.
// It delegates concurrency (channels, heartbeats, etc.) to the shared ScanTemplate
// and focuses on how to fetch and process remote data.
type Scanner struct {
	template *srcs.ScanTemplate
	detector *detect.Detector
	logger   *logger.Logger
	tracer   trace.Tracer
	metrics  scanning.SourceScanMetrics
}

// NewScanner creates a new scanner with the provided tracer, logger, metrics, and Gitleaks detector.
// We also initialize a shared ScanTemplate to handle concurrency and top-level spans.
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

// ScanStreaming sets up the concurrency flow via the ScanTemplate and then calls runURLScan
// for the actual logic. The returned channels convey heartbeats, findings, and errors.
// TODO: Implement progress reporting.
func (s *Scanner) ScanStreaming(
	ctx context.Context,
	task *dtos.ScanRequest,
	reporter scanning.ProgressReporter,
) (<-chan struct{}, <-chan scanning.Finding, <-chan error) {
	opts := srcs.TemplateOptions{
		OperationName: "gitleaks_url_scanner.scan",
		OperationAttributes: []attribute.KeyValue{
			attribute.String("url", task.ResourceURI),
		},
		HeartbeatInterval: 5 * time.Second,
	}
	return s.template.ScanStreaming(ctx, task, opts, reporter, s.runURLScan)
}

// runURLScan encapsulates the main scanning logic, including fetching data
// via HTTP and optionally extracting archives before scanning them with Gitleaks.
func (s *Scanner) runURLScan(
	ctx context.Context,
	task *dtos.ScanRequest,
	findingsChan chan<- scanning.Finding,
	reporter scanning.ProgressReporter,
) error {
	ctx, span := s.tracer.Start(ctx, "gitleaks_url_scanner.scan_main",
		trace.WithAttributes(attribute.String("url", task.ResourceURI)))
	defer span.End()

	startTime := time.Now()
	defer func() {
		s.metrics.ObserveScanDuration(ctx, shared.SourceType(task.SourceType), time.Since(startTime))
	}()

	var sequenceNum atomic.Int64
	if seqStr, ok := task.Metadata["sequence_num"]; ok {
		if seqVal, err := strconv.ParseInt(seqStr, 10, 64); err == nil {
			sequenceNum.Store(seqVal)
		}
	}

	var resumeFileIdx int64
	// If you store a "resume_file_idx" in metadata,
	// parse that too if your source uses it.
	if idxStr, ok := task.Metadata["resume_file_index"]; ok {
		if idxVal, err := strconv.ParseInt(idxStr, 10, 64); err == nil {
			span.SetAttributes(attribute.Int64("resume_file_index", idxVal))
			resumeFileIdx = idxVal
		}
	}

	scanCtx := NewScanContext(task.TaskID, resumeFileIdx, &sequenceNum, reporter)

	format := "none"
	if formatStr, ok := task.Metadata["archive_format"]; ok {
		format = formatStr
	}
	span.SetAttributes(attribute.String("archive_format", format))

	// Prepare a specialized ArchiveReader based on format (e.g., "warc.gz")
	reader, err := s.createArchiveReader(ctx, format, task, scanCtx)
	if err != nil {
		s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
		return err
	}
	defer reader.Close()

	_, detectSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.detect_secrets")
	detectSpan.AddEvent("gitleaks_detection_started")

	// Gitleaks can read from an io.Reader. (the decompressed or raw data)
	findings, err := s.detector.DetectReader(reader, 32)
	if err != nil {
		detectSpan.RecordError(err)
		detectSpan.End()
		s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
		return fmt.Errorf("failed to scan URL: %w", err)
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

	s.metrics.ObserveScanFindings(ctx, shared.SourceType(task.SourceType), len(findings))
	detectSpan.AddEvent("findings_processed",
		trace.WithAttributes(attribute.Int("findings.count", len(findings))))
	detectSpan.End()

	s.logger.Info(ctx, "found findings in URL-based data",
		"url", task.ResourceURI,
		"num_findings", len(findings),
	)

	span.SetStatus(codes.Ok, "scan_completed")
	return nil
}

// ScanContext holds shared state for a single scanning operation.
// It can track the next sequence number, the progress reporter, and optional resume offsets.
type ScanContext struct {
	taskID        uuid.UUID
	reporter      scanning.ProgressReporter
	nextSequence  *atomic.Int64
	resumeFileIdx int64
}

// NewScanContext constructs a ScanContext, typically called once at the start of a scan.
func NewScanContext(
	taskID uuid.UUID,
	resumeFileIdx int64,
	resumeSequence *atomic.Int64,
	reporter scanning.ProgressReporter,
) *ScanContext {
	return &ScanContext{
		taskID:        taskID,
		reporter:      reporter,
		nextSequence:  resumeSequence,
		resumeFileIdx: resumeFileIdx,
	}
}

// NextSequence increments and returns the next sequence number for progress events.
func (sc *ScanContext) NextSequence() int64 { return sc.nextSequence.Add(1) }

// ReportProgress emits a progress event with the current sequence number
// and any other relevant data.
func (sc *ScanContext) ReportProgress(ctx context.Context, itemsProcessed int64, message string) {
	span := trace.SpanFromContext(ctx)
	seqNum := sc.NextSequence()

	span.SetAttributes(
		attribute.Int64("sequence_num", seqNum),
		attribute.Int64("items_processed", itemsProcessed),
		attribute.String("message", message),
	)

	// Create metadata map for the checkpoint.
	metadata := map[string]string{
		"file_index": strconv.FormatInt(itemsProcessed, 10),
	}

	if err := sc.reporter.ReportProgress(
		ctx,
		domain.NewProgress(
			sc.taskID,
			seqNum,
			time.Now(),
			itemsProcessed,
			0, // TODO: address error counts
			message,
			nil, // TODO: address progress details. Do we need this?
			domain.NewCheckpoint(
				sc.taskID,
				[]byte(strconv.FormatInt(itemsProcessed, 10)),
				metadata,
			),
		),
	); err != nil {
		span.RecordError(err)
		return
	}
	span.AddEvent("progress_reported")
}

// createArchiveReader performs an HTTP GET and then wraps the response Body
// in an ArchiveReader if needed (e.g., WARC, gzipped).
func (s *Scanner) createArchiveReader(
	ctx context.Context,
	format string,
	task *dtos.ScanRequest,
	scanCtx *ScanContext,
) (io.ReadCloser, error) {
	_, archiveSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.create_archive_reader")
	defer archiveSpan.End()

	// TODO: Abstract all this crap away.
	archiveReader, err := newArchiveReader(format, func(size int64) {
		s.metrics.ObserveScanSize(ctx, shared.SourceType(task.SourceType), size)
	}, s.tracer)
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
		s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
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
func newArchiveReader(format string, sizeCallback func(int64), tracer trace.Tracer) (ArchiveReader, error) {
	switch format {
	case "warc.gz":
		return newWarcGzReader(sizeCallback, tracer), nil
	case "none", "":
		return new(PassthroughReader), nil
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", format)
	}
}

// WarcGzReader is a struct that implements the ArchiveReader interface.
// It reads WARC.GZ files.
type WarcGzReader struct {
	sizeCallback func(int64) // Callback to report final size
	tracer       trace.Tracer
}

func newWarcGzReader(
	sizeCallback func(int64),
	tracer trace.Tracer,
) *WarcGzReader {
	return &WarcGzReader{sizeCallback: sizeCallback, tracer: tracer}
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

	warcReader, err := gowarc.NewWarcFileReaderFromStream(input, 0)
	if err != nil {
		readSpan.RecordError(err)
		return nil, fmt.Errorf("failed to create WARC reader: %w", err)
	}
	readSpan.AddEvent("warc_reader_created")

	// Uses a pipe to concurrently process WARC records while streaming their contents.
	// This allows memory-efficient processing of large WARC files by reading and consuming
	// records simultaneously rather than loading the entire file into memory.
	pr, pw := io.Pipe()
	bw := bufio.NewWriter(pw)

	go func() {
		span := trace.SpanFromContext(ctx)
		var totalSize int64

		defer func() {
			if w.sizeCallback != nil {
				w.sizeCallback(totalSize)
			}
			bw.Flush()
			pw.Close()
			warcReader.Close()
		}()

		var recordCount int64

		span.AddEvent("warc_reader_processing_started")
		for {
			if ctx.Err() != nil {
				span.AddEvent("context_cancelled")
				pw.CloseWithError(ctx.Err())
				return
			}

			record, _, _, err := warcReader.Next()
			if errors.Is(err, io.EOF) {
				span.AddEvent("warc_reader_processing_finished")
				return
			}
			if err != nil {
				span.AddEvent("failed_to_read_warc_record")
				pw.CloseWithError(fmt.Errorf("failed to read WARC record: %w", err))
				return
			}

			if record.Type() != gowarc.Response {
				span.AddEvent("skipping_non_response_record")
				continue
			}
			recordCount++
			if recordCount < scanCtx.resumeFileIdx {
				span.AddEvent("file_already_processed_skipping")
				continue
			}

			scanCtx.ReportProgress(ctx, recordCount, fmt.Sprintf("Processing WARC record %d", recordCount))

			span.AddEvent("warc_record_processed")

			bodyReader, err := record.Block().RawBytes()
			if err != nil {
				span.AddEvent("failed_to_get_record_body")
				pw.CloseWithError(fmt.Errorf("failed to get record body: %w", err))
				return
			}

			size, err := io.Copy(bw, bodyReader)
			if err != nil {
				span.AddEvent("failed_to_copy_record_body")
				pw.CloseWithError(fmt.Errorf("failed to copy record body: %w", err))
				return
			}

			totalSize += size // Accumulate total size

			span.AddEvent("record_body_copied", trace.WithAttributes(attribute.Int64("record_body_length", size)))
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
