package url

import (
	"bufio"
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

	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Scanner is a struct that implements SecretScanner for URL-based sources.
// It contains a Gitleaks detector, a logger, a tracer, and a metrics interface.
type Scanner struct {
	detector *detect.Detector
	logger   *logger.Logger
	tracer   trace.Tracer
	metrics  scanning.SourceScanMetrics
}

// NewScanner creates a new Scanner instance.
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

// ScanStreaming performs asynchronous secret scanning on a URL and streams the results
// through three channels:
//   - A heartbeat channel indicating the scanner is still active
//   - A findings channel emitting discovered secrets in real-time
//   - An error channel reporting any scanning failures
//
// The scanner fetches data from the provided URL and streams it through the Gitleaks
// detector. As secrets are found, they are logged and metrics are recorded. Progress
// is reported via the provided reporter interface. The scan runs until completion,
// context cancellation, or an error occurs.
//
// To prevent goroutine leaks, callers must consume from all channels until they
// are closed.
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

		ctx, span := s.tracer.Start(ctx, "gitleaks_url_scanner.scan",
			trace.WithAttributes(
				attribute.String("url", task.ResourceURI),
			))
		startTime := time.Now()
		defer func() {
			span.End()
			s.metrics.ObserveScanDuration(ctx, shared.SourceType(task.SourceType), time.Since(startTime))
		}()

		format := "none"
		if formatStr, ok := task.Metadata["archive_format"]; ok {
			format = formatStr
		}
		span.SetAttributes(attribute.String("archive_format", format))

		// TODO: Abstract all this crap away.
		// Ideally, we have a single component that can handle any archive format.
		_, archiveSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.create_archive_reader")
		archiveReader, err := newArchiveReader(format, func(size int64) {
			s.metrics.ObserveScanSize(ctx, shared.SourceType(task.SourceType), size)
		}, s.tracer)
		if err != nil {
			archiveSpan.RecordError(err)
			archiveSpan.End()
			s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
			errChan <- fmt.Errorf("failed to create archive reader: %w", err)
			return
		}
		archiveSpan.End()

		scanComplete := make(chan error, 1)
		go func() {
			defer close(scanComplete)

			_, httpSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.http_request",
				trace.WithSpanKind(trace.SpanKindClient))
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, task.ResourceURI, nil)
			if err != nil {
				httpSpan.RecordError(err)
				httpSpan.End()
				s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
				scanComplete <- fmt.Errorf("failed to create HTTP request: %w", err)
				return
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				httpSpan.RecordError(err)
				httpSpan.SetAttributes(attribute.String("error", err.Error()))
				httpSpan.End()
				s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
				scanComplete <- fmt.Errorf("failed to execute HTTP request: %w", err)
				return
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
				s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
				scanComplete <- fmt.Errorf("failed to fetch URL: %s", errMsg)
				return
			}

			processCtx, processSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.process_archive")
			reader, err := archiveReader.Read(processCtx, resp.Body)
			if err != nil {
				processSpan.RecordError(err)
				processSpan.End()
				s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
				scanComplete <- fmt.Errorf("failed to process archive: %w", err)
				return
			}
			processSpan.End()

			_, detectSpan := s.tracer.Start(ctx, "gitleaks_url_scanner.detect_secrets")
			detectSpan.AddEvent("gitleaks_detection_started")
			findings, err := s.detector.DetectReader(reader, 32)
			if err != nil {
				detectSpan.RecordError(err)
				detectSpan.End()
				s.metrics.IncScanError(ctx, shared.SourceType(task.SourceType))
				scanComplete <- fmt.Errorf("failed to scan URL: %w", err)
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
			detectSpan.AddEvent("findings_processed",
				trace.WithAttributes(attribute.Int("findings.count", len(findings))))
			detectSpan.End()

			s.logger.Info(ctx, "found findings in URL-based data",
				"url", task.ResourceURI,
				"num_findings", len(findings),
			)

			span.SetStatus(codes.Ok, "scan_completed")
			scanComplete <- nil
		}()

		// Handle events.
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

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
