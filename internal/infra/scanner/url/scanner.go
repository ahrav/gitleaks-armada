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
	ObserveFindings(ctx context.Context, repoURI string, findings int)

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

// Scan is a method of the Scanner struct.
// It fetches data from the URL, then streams it into the Gitleaks detector.
// It also records the number of findings in a repository and logs the findings.
func (s *Scanner) Scan(ctx context.Context, task *dtos.ScanRequest) error {
	ctx, span := s.tracer.Start(ctx, "gitleaks_scanner.scan.url",
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

	// Create size tracking callback
	sizeTracker := func(size int64) {
		s.metrics.ObserveURLScanSize(ctx, task.ResourceURI, size)
	}

	archiveReader, err := newArchiveReader(format, sizeTracker)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create archive reader: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, task.ResourceURI, nil)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// TODO: Use a custom HTTP client.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.String("error", err.Error()))
		return fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer resp.Body.Close()
	span.SetAttributes(attribute.Int("response_status_code", resp.StatusCode))
	span.SetAttributes(attribute.String("response_status", resp.Status))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg := fmt.Sprintf("received non-2xx response code %d", resp.StatusCode)
		span.RecordError(errors.New(errMsg))
		span.SetAttributes(attribute.String("error", errMsg))
		return fmt.Errorf("failed to fetch URL: %s", errMsg)
	}

	reader, err := archiveReader.Read(ctx, resp.Body)
	if err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.String("error", err.Error()))
		return fmt.Errorf("failed to process archive: %w", err)
	}

	findings, err := s.detector.DetectReader(reader, 32)
	if err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.String("error", err.Error()))
		return fmt.Errorf("failed to scan URL: %w", err)
	}

	s.metrics.ObserveFindings(ctx, task.ResourceURI, len(findings))
	span.AddEvent("findings_processed", trace.WithAttributes(attribute.Int("findings.count", len(findings))))

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
}

// Read is a method of the WarcGzReader struct.
// It reads from an input stream and returns a reader and an error.
func (w *WarcGzReader) Read(ctx context.Context, input io.Reader) (io.Reader, error) {
	span := trace.SpanFromContext(ctx)

	warcReader, err := gowarc.NewWarcFileReaderFromStream(input, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create WARC reader: %w", err)
	}
	span.AddEvent("warc_reader_created")

	var totalSize int64
	pr, pw := io.Pipe()
	go func() {
		defer func() {
			if w.sizeCallback != nil {
				w.sizeCallback(totalSize) // Report final size when done
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
func newArchiveReader(format string, sizeCallback func(int64)) (ArchiveReader, error) {
	switch format {
	case "warc.gz":
		return &WarcGzReader{sizeCallback: sizeCallback}, nil
	case "none", "":
		return new(PassthroughReader), nil
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", format)
	}
}
