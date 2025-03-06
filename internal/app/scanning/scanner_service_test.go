package scanning

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// mockScannerRepository is a mock implementation of domain.ScannerRepository.
type mockScannerRepository struct{ mock.Mock }

func (m *mockScannerRepository) CreateScannerGroup(ctx context.Context, group *domain.ScannerGroup) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}

func (m *mockScannerRepository) CreateScanner(ctx context.Context, scanner *domain.Scanner) error {
	args := m.Called(ctx, scanner)
	return args.Error(0)
}

// newScannerService creates a test instance of the scanner service with mocked dependencies.
func newScannerService(t *testing.T) (*scannerService, *mockScannerRepository) {
	mockRepo := new(mockScannerRepository)
	log := logger.New(io.Discard, logger.LevelDebug, "test", nil)
	tracer := noop.NewTracerProvider().Tracer("test")

	service := NewScannerService("test-controller", mockRepo, log, tracer)
	return service, mockRepo
}

func TestCreateScannerGroup(t *testing.T) {
	tests := []struct {
		name        string
		groupName   string
		description string
		setup       func(*mockScannerRepository)
		wantErr     bool
	}{
		{
			name:        "successful_creation",
			groupName:   "Test Group",
			description: "This is a test group",
			setup: func(repo *mockScannerRepository) {
				repo.On("CreateScannerGroup", mock.Anything, mock.AnythingOfType("*scanning.ScannerGroup")).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "name_too_short",
			groupName:   "",
			description: "Valid description",
			setup:       func(repo *mockScannerRepository) {}, // No repository call expected for validation errors.
			wantErr:     true,
		},
		{
			name:        "name_too_long",
			groupName:   "This name is way too long and exceeds the maximum length allowed for scanner group names in our system",
			description: "Valid description",
			setup:       func(repo *mockScannerRepository) {}, // No repository call expected for validation errors.
			wantErr:     true,
		},
		{
			name:        "invalid_name_characters",
			groupName:   "Test@Group!",
			description: "Valid description",
			setup:       func(repo *mockScannerRepository) {}, // No repository call expected for validation errors.
			wantErr:     true,
		},
		{
			name:        "description_too_long",
			groupName:   "Valid Name",
			description: string(make([]rune, 201)),            // One more than maxDescriptionLength (200)
			setup:       func(repo *mockScannerRepository) {}, // No repository call expected for validation errors.
			wantErr:     true,
		},
		{
			name:        "repository_error",
			groupName:   "Valid Group",
			description: "Valid description",
			setup: func(repo *mockScannerRepository) {
				repo.On("CreateScannerGroup", mock.Anything, mock.AnythingOfType("*scanning.ScannerGroup")).
					Return(errors.New("database error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := newScannerService(t)
			tt.setup(mockRepo)

			cmd := domain.NewCreateScannerGroupCommand(tt.groupName, tt.description)
			group, err := service.CreateScannerGroup(context.Background(), cmd)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, group)
			} else {
				require.NoError(t, err)
				require.NotNil(t, group)
				assert.Equal(t, tt.groupName, group.Name())
				assert.Equal(t, tt.description, group.Description())
				assert.NotEqual(t, uuid.UUID{}, group.ID())
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestCreateScanner(t *testing.T) {
	tests := []struct {
		name        string
		groupName   string
		scannerName string
		version     string
		metadata    map[string]any
		setup       func(*mockScannerRepository)
		wantErr     bool
	}{
		{
			name:        "successful_creation",
			groupName:   "Test Group",
			scannerName: "Test Scanner",
			version:     "1.0.0",
			metadata:    map[string]any{"region": "us-west", "capabilities": []string{"git", "s3"}},
			setup: func(repo *mockScannerRepository) {
				repo.On("CreateScanner", mock.Anything, mock.AnythingOfType("*scanning.Scanner")).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "name_too_short",
			groupName:   "Test Group",
			scannerName: "",
			version:     "1.0.0",
			metadata:    nil,
			setup:       func(repo *mockScannerRepository) {}, // No repository call expected for validation errors
			wantErr:     true,
		},
		{
			name:        "name_too_long",
			groupName:   "Test Group",
			scannerName: "This scanner name is way too long and exceeds the maximum length allowed for scanner names in our system",
			version:     "1.0.0",
			metadata:    nil,
			setup:       func(repo *mockScannerRepository) {}, // No repository call expected for validation errors
			wantErr:     true,
		},
		{
			name:        "invalid_name_characters",
			groupName:   "Test Group",
			scannerName: "Test$Scanner*",
			version:     "1.0.0",
			metadata:    nil,
			setup:       func(repo *mockScannerRepository) {}, // No repository call expected for validation errors
			wantErr:     true,
		},
		{
			name:        "version_too_long",
			groupName:   "Test Group",
			scannerName: "Valid Scanner",
			version:     "1.0.0-alpha-this-is-too-long-for-a-version-string",
			metadata:    nil,
			setup:       func(repo *mockScannerRepository) {}, // No repository call expected for validation errors
			wantErr:     true,
		},
		{
			name:        "nil_metadata_initialized",
			groupName:   "Test Group",
			scannerName: "Valid Scanner",
			version:     "1.0.0",
			metadata:    nil,
			setup: func(repo *mockScannerRepository) {
				repo.On("CreateScanner", mock.Anything, mock.AnythingOfType("*scanning.Scanner")).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "repository_error",
			groupName:   "Test Group",
			scannerName: "Valid Scanner",
			version:     "1.0.0",
			metadata:    map[string]any{"region": "eu-central"},
			setup: func(repo *mockScannerRepository) {
				repo.On("CreateScanner", mock.Anything, mock.AnythingOfType("*scanning.Scanner")).
					Return(errors.New("database error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockRepo := newScannerService(t)
			tt.setup(mockRepo)

			cmd := domain.NewCreateScannerCommand(tt.groupName, tt.scannerName, tt.version, tt.metadata)
			scanner, err := service.CreateScanner(context.Background(), cmd)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, scanner)
			} else {
				require.NoError(t, err)
				require.NotNil(t, scanner)
				assert.Equal(t, tt.scannerName, scanner.Name())
				assert.Equal(t, tt.version, scanner.Version())
				assert.NotEqual(t, uuid.UUID{}, scanner.ID())

				assert.NotNil(t, scanner.Metadata())
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
