package scanning

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// ScannerConfig encapsulates the configuration parameters for a scanner.
// It contains identification and capability information that defines
// how the scanner presents itself to the registration system.
type ScannerConfig struct {
	// Name is the unique identifier for this scanner instance.
	Name string
	// GroupName is the logical group this scanner belongs to.
	GroupName string
	// Hostname is the network identifier for this scanner.
	Hostname string
	// Version indicates the scanner software version.
	Version string
	// Capabilities specifies what types of scanning this instance can perform.
	Capabilities []string
}

// ScannerRegistrar handles the registration of scanners with the controller.
// It manages scanner identity, capabilities, and publishing registration events
// to make scanners available for scanning operations.
type ScannerRegistrar struct {
	scannerName      string
	scannerGroupName string
	hostname         string
	capabilities     []string
	version          string

	publisher events.DomainEventPublisher

	logger *logger.Logger
	tracer trace.Tracer
}

// NewScannerRegistrar creates a new scanner registration service.
// It initializes a scanner with the provided configuration,
// along with default capabilities for secrets and SAST scanning.
//
// The scanner name is automatically generated based on the hostname.
func NewScannerRegistrar(
	config ScannerConfig,
	publisher events.DomainEventPublisher,
	logger *logger.Logger,
	tracer trace.Tracer,
) *ScannerRegistrar {
	return &ScannerRegistrar{
		scannerName:      config.Name,
		scannerGroupName: config.GroupName,
		hostname:         config.Hostname,
		publisher:        publisher,
		capabilities:     config.Capabilities,
		version:          config.Version,
		logger:           logger.With("component", "scanner_registration"),
		tracer:           tracer,
	}
}

// Register sends a scanner registration event to the controller.
// This informs the system that a scanner is online and available for scanning jobs,
// providing details about its capabilities and identification information.
//
// The registration process includes OpenTelemetry instrumentation for observability.
// If the event fails to publish, an error is returned and recorded in the span.
func (s *ScannerRegistrar) Register(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "scanner.registration.register",
		trace.WithAttributes(
			attribute.String("scanner_name", s.scannerName),
			attribute.String("hostname", s.hostname),
			attribute.String("group_name", s.scannerGroupName),
		))
	defer span.End()

	s.logger.Info(ctx, "Registering scanner",
		"scanner_name", s.scannerName,
		"hostname", s.hostname,
		"group_name", s.scannerGroupName)

	regEvent := scanning.NewScannerRegisteredEvent(
		s.scannerName,
		s.version,
		s.capabilities,
		s.hostname,
		s.hostname,
		s.scannerGroupName,
		nil,
		scanning.ScannerStatusOnline,
	)

	err := s.publisher.PublishDomainEvent(
		ctx,
		regEvent,
		events.WithKey(fmt.Sprintf("%s:%s", s.scannerName, s.scannerGroupName)),
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish registration event")
		return fmt.Errorf("failed to publish registration event: %w", err)
	}

	span.AddEvent("scanner_registration_event_published")
	span.SetStatus(codes.Ok, "scanner registration event published")
	s.logger.Info(ctx, "Scanner registration event published")

	return nil
}
