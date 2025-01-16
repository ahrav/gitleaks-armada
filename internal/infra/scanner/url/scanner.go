package url

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nlnwa/gowarc"
	"github.com/zricethezav/gitleaks/v8/detect"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// metrics is an interface that defines operations for URL-based sources.
type metrics interface {
	// ObserveFindings records the number of findings in a repository.
	ObserveURLFindings(ctx context.Context, url string, count int)

	// ObserveURLScanTime records the time taken to scan a URL.
	ObserveURLScanTime(ctx context.Context, url string, duration time.Duration)

	// ObserveURLScanSize records the size of a URL.
	ObserveURLScanSize(ctx context.Context, url string, sizeBytes int64)
}

// Scanner is a struct that implements SecretScanner for URL-based sources.
// It contains a Gitleaks detector, a logger, a tracer, and a metrics interface.
type Scanner struct {
	detector *detect.Detector
	logger   *logger.Logger
	tracer   trace.Tracer
	metrics  metrics
}

// NewScanner creates a new Scanner instance.
func NewScanner(detector *detect.Detector, logger *logger.Logger, tracer trace.Tracer, metrics metrics) *Scanner {
	return &Scanner{
		detector: detector,
		logger:   logger,
		tracer:   tracer,
		metrics:  metrics,
	}
}

// Scan is a method of the Scanner struct.
// It fetches data from the URL, then streams it into the Gitleaks detector.
// It also records the number of findings in a repository and logs the findings.
func (s *Scanner) Scan(ctx context.Context, task *dtos.ScanRequest) error {
	ctx, span := s.tracer.Start(ctx, "gitleaks_url_scanner.scan",
		trace.WithAttributes(
			attribute.String("url", task.ResourceURI),
		))
	startTime := time.Now()
	defer func() {
		span.End()
		s.metrics.ObserveURLScanTime(ctx, task.ResourceURI, time.Since(startTime))
	}()

	format := "none"
	if formatStr, ok := task.Metadata["archive_format"]; ok {
		format = formatStr
	}
	span.SetAttributes(attribute.String("archive_format", format))

	_, archiveSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.create_archive_reader")
	archiveReader, err := newArchiveReader(format, func(size int64) {
		s.metrics.ObserveURLScanSize(ctx, task.ResourceURI, size)
	}, s.tracer)
	if err != nil {
		archiveSpan.RecordError(err)
		archiveSpan.End()
		return fmt.Errorf("failed to create archive reader: %w", err)
	}
	archiveSpan.End()

	_, httpSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.http_request", trace.WithSpanKind(trace.SpanKindClient))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, task.ResourceURI, nil)
	if err != nil {
		httpSpan.RecordError(err)
		httpSpan.End()
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		httpSpan.RecordError(err)
		httpSpan.SetAttributes(attribute.String("error", err.Error()))
		httpSpan.End()
		return fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer resp.Body.Close()

	httpSpan.SetAttributes(
		attribute.Int("response_status_code", resp.StatusCode),
		attribute.String("response_status", resp.Status),
	)
	httpSpan.End()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg := fmt.Sprintf("received non-2xx response code %d", resp.StatusCode)
		span.RecordError(errors.New(errMsg))
		return fmt.Errorf("failed to fetch URL: %s", errMsg)
	}

	processCtx, processSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.process_archive")
	reader, err := archiveReader.Read(processCtx, resp.Body)
	if err != nil {
		processSpan.RecordError(err)
		processSpan.End()
		return fmt.Errorf("failed to process archive: %w", err)
	}
	processSpan.End()

	_, detectSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.detect_secrets")
	detectSpan.AddEvent("gitleaks_detection_started")
	findings, err := s.detector.DetectReader(reader, 32)
	if err != nil {
		detectSpan.RecordError(err)
		detectSpan.End()
		return fmt.Errorf("failed to scan URL: %w", err)
	}

	s.metrics.ObserveURLFindings(ctx, task.ResourceURI, len(findings))
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

// ArchiveReader is an interface for archive readers.
// It defines a method for reading from an input stream.
type ArchiveReader interface {
	Read(ctx context.Context, input io.Reader) (io.Reader, error)
}

// WarcGzReader is a struct that implements the ArchiveReader interface.
// It reads WARC.GZ files.
type WarcGzReader struct {
	sizeCallback func(int64) // Callback to report final size
	tracer       trace.Tracer
}

// Read is a method of the WarcGzReader struct.
// It reads from an input stream and returns a reader and an error.
func (w *WarcGzReader) Read(ctx context.Context, input io.Reader) (io.Reader, error) {
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

	go func() {
		span := trace.SpanFromContext(ctx)

		defer func() {
			if w.sizeCallback != nil {
				w.sizeCallback(totalSize)
			}
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

			body, err := record.Block().RawBytes()
			if err != nil {
				span.AddEvent("failed_to_get_record_body")
				pw.CloseWithError(fmt.Errorf("failed to get record body: %w", err))
				return
			}

			_, err = io.Copy(pw, body)
			if err != nil {
				span.AddEvent("failed_to_copy_record_body")
				pw.CloseWithError(fmt.Errorf("failed to copy record body: %w", err))
				return
			}

			size := int64(record.Block().Size())
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
func (p *PassthroughReader) Read(ctx context.Context, input io.Reader) (io.Reader, error) {
	return input, nil
}

// newArchiveReader is a factory function that creates an appropriate reader based on the format string.
// It returns an ArchiveReader and an error.
func newArchiveReader(format string, sizeCallback func(int64), tracer trace.Tracer) (ArchiveReader, error) {
	switch format {
	case "warc.gz":
		return &WarcGzReader{sizeCallback: sizeCallback, tracer: tracer}, nil
	case "none", "":
		return new(PassthroughReader), nil
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", format)
	}
}
