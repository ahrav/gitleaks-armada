package scanning

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// mockDomainScannerService mocks the domain.ScannerService for testing.
type mockDomainScannerService struct{ mock.Mock }

func (m *mockDomainScannerService) CreateScannerGroup(ctx context.Context, cmd domain.CreateScannerGroupCommand) (*domain.ScannerGroup, error) {
	args := m.Called(ctx, cmd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.ScannerGroup), args.Error(1)
}

func (m *mockDomainScannerService) CreateScanner(ctx context.Context, cmd domain.CreateScannerCommand) (*domain.Scanner, error) {
	args := m.Called(ctx, cmd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Scanner), args.Error(1)
}

func TestCreateScannerGroup(t *testing.T) {
	mockService := new(mockDomainScannerService)
	log := logger.New(io.Discard, logger.LevelDebug, "test", nil)
	apiService := NewScannerService(log, mockService)

	tests := []struct {
		name          string
		groupName     string
		description   string
		mockSetup     func()
		wantError     error
		errorContains string
	}{
		{
			name:        "successful_creation",
			groupName:   "Test Group",
			description: "Test Description",
			mockSetup: func() {
				groupID := uuid.New()
				group, _ := domain.NewScannerGroup(groupID, "Test Group", "Test Description")
				mockService.On("CreateScannerGroup", mock.Anything, mock.MatchedBy(func(cmd domain.CreateScannerGroupCommand) bool {
					return cmd.Name == "Test Group" && cmd.Description == "Test Description"
				})).Return(group, nil).Once()
			},
			wantError: nil,
		},
		{
			name:        "duplicate_scanner_group",
			groupName:   "Existing Group",
			description: "This group already exists",
			mockSetup: func() {
				mockService.On("CreateScannerGroup", mock.Anything, mock.MatchedBy(func(cmd domain.CreateScannerGroupCommand) bool {
					return cmd.Name == "Existing Group" && cmd.Description == "This group already exists"
				})).Return(nil, domain.ErrScannerGroupAlreadyExists).Once()
			},
			wantError: ErrScannerGroupAlreadyExists,
		},
		{
			name:        "validation_error",
			groupName:   "Invalid Group",
			description: "Invalid description",
			mockSetup: func() {
				validationErr := errors.New("validation error")
				mockService.On("CreateScannerGroup", mock.Anything, mock.MatchedBy(func(cmd domain.CreateScannerGroupCommand) bool {
					return cmd.Name == "Invalid Group" && cmd.Description == "Invalid description"
				})).Return(nil, validationErr).Once()
			},
			errorContains: "validation error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			info, err := apiService.CreateScannerGroup(context.Background(), tt.groupName, tt.description)

			if tt.wantError != nil {
				assert.Nil(t, info)
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantError)
			} else if tt.errorContains != "" {
				assert.Nil(t, info)
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.errorContains)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, info)
				assert.Equal(t, tt.groupName, info.Name)
				assert.Equal(t, tt.description, info.Description)
			}
		})
	}

	mockService.AssertExpectations(t)
}
