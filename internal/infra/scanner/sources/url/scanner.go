package url

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nlnwa/gowarc"
	"github.com/zricethezav/gitleaks/v8/detect"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
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

	format := "none"
	if formatStr, ok := task.Metadata["archive_format"]; ok {
		format = formatStr
	}
	span.SetAttributes(attribute.String("archive_format", format))

	// Prepare a specialized ArchiveReader based on format (e.g., "warc.gz")
	reader, err := s.createArchiveReader(ctx, format, task, reporter)
	if err != nil {
		s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
		return err
	}

	_, detectSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.detect_secrets")
	detectSpan.AddEvent("gitleaks_detection_started")

	// Gitleaks can read from an io.Reader (the decompressed or raw data)
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

// createArchiveReader performs an HTTP GET and then wraps the response Body
// in an ArchiveReader if needed (e.g., WARC, gzipped).
func (s *Scanner) createArchiveReader(
	ctx context.Context,
	format string,
	task *dtos.ScanRequest,
	reporter scanning.ProgressReporter,
) (io.Reader, error) {
	_, archiveSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.create_archive_reader")
	defer archiveSpan.End()

	// TODO: Abstract all this crap away.
	archiveReader, err := newArchiveReader(format, func(size int64) {
		s.metrics.ObserveScanSize(ctx, shared.SourceType(task.SourceType), size)
	}, reporter, s.tracer)
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
		errMsg := fmt.Sprintf("non-2xx response code %d", resp.StatusCode)
		httpSpan.RecordError(errors.New(errMsg))
		return nil, fmt.Errorf("failed to fetch URL: %s", errMsg)
	}

	// We'll wrap the response body in our chosen archive reader
	processCtx, processSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.process_archive")
	defer processSpan.End()

	reader, err := archiveReader.Read(processCtx, resp.Body, reporter, task.TaskID)
	if err != nil {
		processSpan.RecordError(err)
		s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
		return nil, fmt.Errorf("failed to process archive: %w", err)
	}
	return reader, nil
}

// ArchiveReader is an interface for archive readers.
// It defines a method for reading from an input stream.
// It also takes a reporter for progress reporting.
type ArchiveReader interface {
	Read(ctx context.Context, input io.Reader, reporter scanning.ProgressReporter, taskID uuid.UUID) (io.Reader, error)
}

// newArchiveReader is a factory function that creates an appropriate reader based on the format string.
// It returns an ArchiveReader and an error.
func newArchiveReader(format string, sizeCallback func(int64), reporter scanning.ProgressReporter, tracer trace.Tracer) (ArchiveReader, error) {
	switch format {
	case "warc.gz":
		return newWarcGzReader(sizeCallback, reporter, tracer), nil
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
	reporter     scanning.ProgressReporter
	tracer       trace.Tracer
}

func newWarcGzReader(
	sizeCallback func(int64),
	reporter scanning.ProgressReporter,
	tracer trace.Tracer,
) *WarcGzReader {
	return &WarcGzReader{sizeCallback: sizeCallback, reporter: reporter, tracer: tracer}
}

// Read is a method of the WarcGzReader struct.
// It reads from an input stream and returns a reader and an error.
func (w *WarcGzReader) Read(
	ctx context.Context,
	input io.Reader,
	reporter scanning.ProgressReporter,
	taskID uuid.UUID,
) (io.Reader, error) {
	ctx, readSpan := w.tracer.Start(ctx, "warc_reader.read")
	defer readSpan.End()

	warcReader, err := gowarc.NewWarcFileReaderFromStream(input, 0)
	if err != nil {
		readSpan.RecordError(err)
		return nil, fmt.Errorf("failed to create WARC reader: %w", err)
	}
	readSpan.AddEvent("warc_reader_created")

	var totalSize int64
	pr, pw := io.Pipe()
	bw := bufio.NewWriter(pw)

	go func() {
		span := trace.SpanFromContext(ctx)

		defer func() {
			if w.sizeCallback != nil {
				w.sizeCallback(totalSize)
			}
			bw.Flush()
			pw.Close()
			warcReader.Close()
		}()

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
	reporter scanning.ProgressReporter,
	taskID uuid.UUID,
) (io.Reader, error) {
	return input, nil
}
