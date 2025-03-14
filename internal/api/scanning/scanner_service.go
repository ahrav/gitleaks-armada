// Package scanning provides API services for scanner operations.
package scanning

import (
	"context"
	"errors"
	"fmt"
	"time"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// ScannerService coordinates scanner operations from the API layer.
type ScannerService struct {
	log            *logger.Logger
	scannerService domain.ScannerService
}

// NewScannerService creates a new scanner service for API operations.
func NewScannerService(
	log *logger.Logger,
	scannerService domain.ScannerService,
) *ScannerService {
	return &ScannerService{
		log:            log,
		scannerService: scannerService,
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
	cmd := domain.CreateScannerGroupCommand{Name: name, Description: description}

	group, err := s.scannerService.CreateScannerGroup(ctx, cmd)
	if err != nil {
		if errors.Is(err, domain.ErrScannerGroupAlreadyExists) {
			s.log.Info(ctx, "Scanner group already exists", "name", name)
			return nil, ErrScannerGroupAlreadyExists
		}

		return nil, fmt.Errorf("failed to create scanner group: %w", err)
	}

	return &ScannerGroupInfo{
		ID:          group.ID().String(),
		Name:        group.Name(),
		Description: group.Description(),
		CreatedAt:   group.CreatedAt().Format(time.RFC3339),
		UpdatedAt:   group.UpdatedAt().Format(time.RFC3339),
	}, nil
}
