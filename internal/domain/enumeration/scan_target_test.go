package enumeration

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

func TestNewScanTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input struct {
			name       string
			targetType shared.TargetType
			targetID   int64
			metadata   map[string]any
		}
		wantErr bool
	}{
		{
			name: "valid scan target",
			input: struct {
				name       string
				targetType shared.TargetType
				targetID   int64
				metadata   map[string]any
			}{
				name:       "test-repo",
				targetType: shared.TargetTypeGitHubRepo,
				targetID:   123,
				metadata: map[string]any{
					"owner": "test-owner",
				},
			},
			wantErr: false,
		},
		{
			name: "empty name",
			input: struct {
				name       string
				targetType shared.TargetType
				targetID   int64
				metadata   map[string]any
			}{
				name:       "",
				targetType: shared.TargetTypeGitHubRepo,
				targetID:   123,
				metadata:   nil,
			},
			wantErr: true,
		},
		{
			name: "empty target type",
			input: struct {
				name       string
				targetType shared.TargetType
				targetID   int64
				metadata   map[string]any
			}{
				name:       "test-repo",
				targetType: "",
				targetID:   123,
				metadata:   nil,
			},
			wantErr: true,
		},
		{
			name: "zero target ID",
			input: struct {
				name       string
				targetType shared.TargetType
				targetID   int64
				metadata   map[string]any
			}{
				name:       "test-repo",
				targetType: shared.TargetTypeGitHubRepo,
				targetID:   0,
				metadata:   nil,
			},
			wantErr: true,
		},
		{
			name: "nil metadata is valid",
			input: struct {
				name       string
				targetType shared.TargetType
				targetID   int64
				metadata   map[string]any
			}{
				name:       "test-repo",
				targetType: shared.TargetTypeGitHubRepo,
				targetID:   123,
				metadata:   nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := NewScanTarget(
				tt.input.name,
				tt.input.targetType,
				tt.input.targetID,
				tt.input.metadata,
			)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, target)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, target)
			assert.Equal(t, tt.input.name, target.Name())
			assert.Equal(t, tt.input.targetType, target.TargetType())
			assert.Equal(t, tt.input.targetID, target.TargetID())
			assert.Equal(t, tt.input.metadata, target.Metadata())
			assert.NotZero(t, target.CreatedAt())
			assert.NotZero(t, target.UpdatedAt())
		})
	}
}

func TestReconstructScanTarget(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	timeline := NewTimeline(&mockTimeProvider{current: fixedTime})

	lastScan := fixedTime.Add(-1 * time.Hour)
	metadata := map[string]any{"key": "value"}
	id := uuid.New()

	target := ReconstructScanTarget(
		id,
		"test-repo",
		shared.TargetTypeGitHubRepo,
		456,
		&lastScan,
		metadata,
		timeline,
	)

	assert.NotNil(t, target)
	assert.Equal(t, id, target.ID())
	assert.Equal(t, "test-repo", target.Name())
	assert.Equal(t, shared.TargetTypeGitHubRepo, target.TargetType())
	assert.Equal(t, int64(456), target.TargetID())
	assert.Equal(t, &lastScan, target.LastScanTime())
	assert.Equal(t, metadata, target.Metadata())
	assert.Equal(t, fixedTime, target.CreatedAt())
	assert.Equal(t, fixedTime, target.UpdatedAt())
}

func TestScanTarget_UpdateLastScanTime(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	newTime := fixedTime.Add(time.Hour)

	mockTimeProvider := &mockTimeProvider{current: fixedTime}

	target, err := NewScanTarget(
		"test-repo",
		shared.TargetTypeGitHubRepo,
		123,
		nil,
	)
	assert.NoError(t, err)

	// Replace the timeline with our controlled version
	target.timeline = NewTimeline(mockTimeProvider)

	// Update the mock provider's time before updating last scan time
	mockTimeProvider.current = newTime

	// Update to a new fixed time
	target.UpdateLastScanTime(newTime)

	require.NotNil(t, target.LastScanTime())
	assert.True(t, target.LastScanTime().Equal(newTime),
		"LastScanTime should equal newTime")
	assert.True(t, target.UpdatedAt().Equal(newTime),
		"UpdatedAt should equal newTime")
}

func TestScanTarget_Getters(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	timeline := NewTimeline(&mockTimeProvider{current: fixedTime})

	lastScan := fixedTime.Add(-1 * time.Hour)
	metadata := map[string]any{"key": "value"}
	id := uuid.New()
	target := ReconstructScanTarget(
		id,
		"test-repo",
		shared.TargetTypeGitHubRepo,
		456,
		&lastScan,
		metadata,
		timeline,
	)

	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"ID", target.ID(), id},
		{"Name", target.Name(), "test-repo"},
		{"TargetType", target.TargetType(), shared.TargetTypeGitHubRepo},
		{"TargetID", target.TargetID(), int64(456)},
		{"LastScanTime", target.LastScanTime(), &lastScan},
		{"Metadata", target.Metadata(), metadata},
		{"CreatedAt", target.CreatedAt(), fixedTime},
		{"UpdatedAt", target.UpdatedAt(), fixedTime},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.got)
		})
	}
}
