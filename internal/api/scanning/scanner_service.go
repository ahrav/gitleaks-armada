// Package scanning provides API services for scanner operations.
package scanning

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// ScannerService coordinates scanner operations from the API layer.
type ScannerService struct {
	scannerService domain.ScannerService

	log    *logger.Logger
	tracer trace.Tracer
}

// NewScannerService creates a new scanner service for API operations.
func NewScannerService(
	scannerService domain.ScannerService,
	log *logger.Logger,
	tracer trace.Tracer,
) *ScannerService {
	return &ScannerService{
		scannerService: scannerService,
		log:            log.With("component", "scanner_service"),
		tracer:         tracer,
	}
}

// ScannerGroupInfo represents a scanner group's information.
type ScannerGroupInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// ErrScannerGroupAlreadyExists indicates a scanner group with the same name already exists.
var ErrScannerGroupAlreadyExists = errors.New("scanner group already exists")

// CreateScannerGroup creates a new scanner group in the system.
func (s *ScannerService) CreateScannerGroup(
	ctx context.Context,
	name string,
	description string,
) (*ScannerGroupInfo, error) {
	ctx, span := s.tracer.Start(ctx, "scanner_service.create_scanner_group",
		trace.WithAttributes(
			attribute.String("name", name),
			attribute.String("description", description),
		),
	)
	defer span.End()
	logger := s.log.With("method", "CreateScannerGroup")

	cmd := domain.CreateScannerGroupCommand{Name: name, Description: description}
	group, err := s.scannerService.CreateScannerGroup(ctx, cmd)
	if err != nil {
		if errors.Is(err, domain.ErrScannerGroupAlreadyExists) {
			span.RecordError(err)
			span.SetStatus(codes.Error, "scanner group already exists")
			logger.Info(ctx, "Scanner group already exists", "name", name)
			return nil, ErrScannerGroupAlreadyExists
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create scanner group")
		return nil, fmt.Errorf("failed to create scanner group: %w", err)
	}
	span.AddEvent("scanner_group_created", trace.WithAttributes(
		attribute.String("group_id", group.ID().String()),
	))

	return &ScannerGroupInfo{
		ID:          group.ID().String(),
		Name:        group.Name(),
		Description: group.Description(),
		CreatedAt:   group.CreatedAt().Format(time.RFC3339),
		UpdatedAt:   group.UpdatedAt().Format(time.RFC3339),
	}, nil
}
