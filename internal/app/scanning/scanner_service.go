package scanning

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

var _ domain.ScannerService = (*scannerService)(nil)

// scannerService implements domain.ScannerService by providing scanner and
// scanner group management with domain validation rules.
type scannerService struct {
	controllerID string

	// scannerRepo provides persistence for Scanner and ScannerGroup entities.
	scannerRepo domain.ScannerRepository

	logger *logger.Logger
	tracer trace.Tracer
}

// NewScannerService creates a service that manages scanner and scanner group entities,
// enforcing domain validation rules and leveraging the provided repository for persistence.
func NewScannerService(
	controllerID string,
	scannerRepo domain.ScannerRepository,
	logger *logger.Logger,
	tracer trace.Tracer,
) *scannerService {
	logger = logger.With("component", "scanner_service")
	return &scannerService{
		controllerID: controllerID,
		scannerRepo:  scannerRepo,
		logger:       logger,
		tracer:       tracer,
	}
}

// CreateScannerGroup creates a new scanner group with validation.
// It uses the domain entity's validation logic and persists the group if valid.
func (s *scannerService) CreateScannerGroup(
	ctx context.Context,
	cmd domain.CreateScannerGroupCommand,
) (*domain.ScannerGroup, error) {
	ctx, span := s.tracer.Start(ctx, "scanner_service.create_scanner_group",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("name", cmd.Name),
		),
	)
	defer span.End()

	groupID := uuid.New()
	group, err := domain.NewScannerGroup(groupID, cmd.Name, cmd.Description)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid scanner group parameters")
		return nil, fmt.Errorf("invalid scanner group parameters (name: %s, id: %s): %w",
			cmd.Name,
			groupID,
			err,
		)
	}
	span.AddEvent("scanner_group_created", trace.WithAttributes(
		attribute.String("group_id", group.ID().String()),
	))

	if err := s.scannerRepo.CreateScannerGroup(ctx, group); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create scanner group")
		return nil, fmt.Errorf(
			"failed to create scanner group (name: %s, id: %s): %w",
			group.Name(),
			group.ID(),
			err,
		)
	}
	span.AddEvent("scanner_group_created")
	span.SetStatus(codes.Ok, "scanner group created successfully")

	return group, nil
}

// CreateScanner registers a new scanner with validation.
// It uses the domain entity's validation logic and persists the scanner if valid.
func (s *scannerService) CreateScanner(
	ctx context.Context,
	cmd domain.CreateScannerCommand,
) (*domain.Scanner, error) {
	ctx, span := s.tracer.Start(ctx, "scanner_service.create_scanner",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("scanner_id", cmd.ScannerID.String()),
			attribute.String("group_name", cmd.GroupName),
			attribute.String("name", cmd.Name),
			attribute.String("version", cmd.Version),
		),
	)
	defer span.End()

	// TODO: Get group ID from group name.
	// Temporarily use a random UUID.
	scanner, err := domain.NewScanner(cmd.ScannerID, uuid.New(), cmd.Name, cmd.Version)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid scanner parameters")
		return nil, fmt.Errorf(
			"invalid scanner parameters (group_name: %s, name: %s, version: %s): %w",
			cmd.GroupName,
			cmd.Name,
			cmd.Version,
			err,
		)
	}
	span.SetAttributes(attribute.String("scanner_id", scanner.ID().String()))
	span.AddEvent("scanner_created")

	if cmd.Metadata != nil {
		scanner.SetMetadata(cmd.Metadata)
	}

	if err := s.scannerRepo.CreateScanner(ctx, scanner); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create scanner")
		return nil, fmt.Errorf(
			"failed to create scanner (group_name: %s, name: %s, version: %s): %w",
			cmd.GroupName,
			cmd.Name,
			cmd.Version,
			err,
		)
	}
	span.AddEvent("scanner_created")
	span.SetStatus(codes.Ok, "scanner created successfully")

	return scanner, nil
}
