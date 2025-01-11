package scanning

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockTimeProvider helps control time in tests
type mockTimeProvider struct {
	currentTime time.Time
}

func (m *mockTimeProvider) Now() time.Time {
	return m.currentTime
}

func TestNewScanTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input struct {
			name       string
			targetType string
			targetID   int64
			metadata   map[string]any
		}
		wantErr bool
	}{
		{
			name: "valid scan target",
			input: struct {
				name       string
				targetType string
				targetID   int64
				metadata   map[string]any
			}{
				name:       "test-repo",
				targetType: "github_repo",
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
				targetType string
				targetID   int64
				metadata   map[string]any
			}{
				name:       "",
				targetType: "github_repo",
				targetID:   123,
				metadata:   nil,
			},
			wantErr: true,
		},
		{
			name: "empty target type",
			input: struct {
				name       string
				targetType string
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
				targetType string
				targetID   int64
				metadata   map[string]any
			}{
				name:       "test-repo",
				targetType: "github_repo",
				targetID:   0,
				metadata:   nil,
			},
			wantErr: true,
		},
		{
			name: "nil metadata is valid",
			input: struct {
				name       string
				targetType string
				targetID   int64
				metadata   map[string]any
			}{
				name:       "test-repo",
				targetType: "github_repo",
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
	timeProvider := &mockTimeProvider{currentTime: fixedTime}
	timeline := NewTimeline(timeProvider)

	lastScan := fixedTime.Add(-1 * time.Hour)
	metadata := map[string]any{"key": "value"}

	target := ReconstructScanTarget(
		123,
		"test-repo",
		"github_repo",
		456,
		&lastScan,
		metadata,
		timeline,
	)

	assert.NotNil(t, target)
	assert.Equal(t, int64(123), target.ID())
	assert.Equal(t, "test-repo", target.Name())
	assert.Equal(t, "github_repo", target.TargetType())
	assert.Equal(t, int64(456), target.TargetID())
	assert.Equal(t, &lastScan, target.LastScanTime())
	assert.Equal(t, metadata, target.Metadata())
	assert.Equal(t, fixedTime, target.CreatedAt())
	assert.Equal(t, fixedTime, target.UpdatedAt())
}

func TestScanTarget_UpdateLastScanTime(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	timeProvider := &mockTimeProvider{currentTime: fixedTime}

	target, err := NewScanTarget(
		"test-repo",
		"github_repo",
		123,
		nil,
	)
	assert.NoError(t, err)

	// Replace the timeline with our controlled version
	target.timeline = NewTimeline(timeProvider)

	// Update to a new fixed time
	newTime := fixedTime.Add(time.Hour)
	timeProvider.currentTime = newTime
	target.UpdateLastScanTime(newTime)

	assert.Equal(t, &newTime, target.LastScanTime())
	assert.Equal(t, newTime, target.UpdatedAt())
}

func TestScanTarget_Getters(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	timeProvider := &mockTimeProvider{currentTime: fixedTime}
	timeline := NewTimeline(timeProvider)

	lastScan := fixedTime.Add(-1 * time.Hour)
	metadata := map[string]any{"key": "value"}

	target := ReconstructScanTarget(
		123,
		"test-repo",
		"github_repo",
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
		{"ID", target.ID(), int64(123)},
		{"Name", target.Name(), "test-repo"},
		{"TargetType", target.TargetType(), "github_repo"},
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
