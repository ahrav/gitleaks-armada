package kafka

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

func TestPosition_Validate(t *testing.T) {
	tests := []struct {
		name      string
		position  Position
		expectErr error
	}{
		{
			name:      "valid position",
			position:  Position{EntityType: scanning.JobMetricsStreamType, Partition: 0, Offset: 0},
			expectErr: nil,
		},
		{
			name:      "invalid entity type",
			position:  Position{EntityType: "", Partition: 0, Offset: 0},
			expectErr: ErrInvalidEntityType{EntityType: ""},
		},
		{
			name:      "invalid partition",
			position:  Position{EntityType: scanning.JobMetricsStreamType, Partition: -1, Offset: 0},
			expectErr: ErrInvalidPartition{Partition: "-1"},
		},
		{
			name:      "invalid offset",
			position:  Position{EntityType: scanning.JobMetricsStreamType, Partition: 0, Offset: -1},
			expectErr: ErrInvalidOffset{Offset: "-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.position.Validate()
			assert.Equal(t, tt.expectErr, err)
		})
	}
}

func TestJobMetricsTranslationRule_Translate(t *testing.T) {
	tests := []struct {
		name        string
		entityID    string
		expected    Position
		expectErr   bool
		expectedErr error
	}{
		{
			name:        "valid entity ID",
			entityID:    "1:100",
			expected:    Position{EntityType: scanning.JobMetricsStreamType, Partition: 1, Offset: 100},
			expectErr:   false,
			expectedErr: nil,
		},
		{
			name:        "invalid format",
			entityID:    "1-100",
			expectErr:   true,
			expectedErr: ErrInvalidPositionFormat{EntityID: "1-100"},
		},
		{
			name:        "invalid partition",
			entityID:    "abc:100",
			expectErr:   true,
			expectedErr: ErrInvalidPartition{Partition: "abc"},
		},
		{
			name:        "invalid offset",
			entityID:    "1:xyz",
			expectErr:   true,
			expectedErr: ErrInvalidOffset{Offset: "xyz"},
		},
	}

	rule := JobMetricsTranslationRule{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := rule.Translate(tt.entityID)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestKafkaPositionTranslator_ToStreamPosition(t *testing.T) {
	tests := []struct {
		name        string
		metadata    events.PositionMetadata
		expected    Position
		expectErr   bool
		expectedErr error
	}{
		{
			name: "valid job metrics entity",
			metadata: events.PositionMetadata{
				EntityType: scanning.JobMetricsStreamType,
				EntityID:   "1:100",
			},
			expected:  Position{EntityType: scanning.JobMetricsStreamType, Partition: 1, Offset: 100},
			expectErr: false,
		},
		{
			name: "unsupported entity type",
			metadata: events.PositionMetadata{
				EntityType: "unsupported",
				EntityID:   "1:100",
			},
			expectErr:   true,
			expectedErr: ErrNoTranslationRule{EntityType: "unsupported"},
		},
	}

	translator := NewKafkaPositionTranslator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := translator.ToStreamPosition(tt.metadata)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
