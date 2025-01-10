package enumeration

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBatchMetrics(t *testing.T) {
	expectedItems := 10

	metrics := NewBatchMetrics(expectedItems)

	assert.Equal(t, expectedItems, metrics.ExpectedItems())
	assert.Equal(t, 0, metrics.ItemsProcessed())
	assert.Empty(t, metrics.ErrorDetails())
}

func TestBatchMetrics_MarkSuccessful(t *testing.T) {
	tests := []struct {
		name           string
		expectedItems  int
		itemsProcessed int
		wantErr        bool
	}{
		{
			name:           "valid number of processed items",
			expectedItems:  10,
			itemsProcessed: 8,
			wantErr:        false,
		},
		{
			name:           "processed equals expected",
			expectedItems:  10,
			itemsProcessed: 10,
			wantErr:        false,
		},
		{
			name:           "processed exceeds expected",
			expectedItems:  10,
			itemsProcessed: 11,
			wantErr:        true,
		},
		{
			name:           "zero processed items",
			expectedItems:  10,
			itemsProcessed: 0,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewBatchMetrics(tt.expectedItems)

			err := metrics.MarkSuccessful(tt.itemsProcessed)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.itemsProcessed, metrics.ItemsProcessed())
			}
		})
	}
}

func TestBatchMetrics_MarkFailed(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantDetails string
	}{
		{
			name:        "with error",
			err:         errors.New("processing failed"),
			wantDetails: "processing failed",
		},
		{
			name:        "with nil error",
			err:         nil,
			wantDetails: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewBatchMetrics(10)

			metrics.MarkFailed(tt.err)

			assert.Equal(t, tt.wantDetails, metrics.ErrorDetails())
			assert.Equal(t, tt.wantDetails != "", metrics.HasError())
		})
	}
}

func TestBatchMetrics_CompletionPercentage(t *testing.T) {
	tests := []struct {
		name           string
		expectedItems  int
		itemsProcessed int
		want           float64
	}{
		{
			name:           "zero expected items",
			expectedItems:  0,
			itemsProcessed: 0,
			want:           0,
		},
		{
			name:           "partial completion",
			expectedItems:  10,
			itemsProcessed: 5,
			want:           50,
		},
		{
			name:           "full completion",
			expectedItems:  10,
			itemsProcessed: 10,
			want:           100,
		},
		{
			name:           "no progress",
			expectedItems:  10,
			itemsProcessed: 0,
			want:           0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewBatchMetrics(tt.expectedItems)
			_ = metrics.MarkSuccessful(tt.itemsProcessed)

			percentage := metrics.CompletionPercentage()

			assert.Equal(t, tt.want, percentage)
		})
	}
}

func TestBatchMetrics_JSON(t *testing.T) {
	tests := []struct {
		name           string
		expectedItems  int
		itemsProcessed int
		errorDetails   error
	}{
		{
			name:           "complete metrics",
			expectedItems:  10,
			itemsProcessed: 5,
			errorDetails:   errors.New("test error"),
		},
		{
			name:           "metrics without error",
			expectedItems:  10,
			itemsProcessed: 10,
			errorDetails:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewBatchMetrics(tt.expectedItems)
			_ = metrics.MarkSuccessful(tt.itemsProcessed)
			if tt.errorDetails != nil {
				metrics.MarkFailed(tt.errorDetails)
			}

			data, err := json.Marshal(metrics)
			require.NoError(t, err)

			var unmarshaled BatchMetrics
			err = json.Unmarshal(data, &unmarshaled)

			require.NoError(t, err)
			assert.Equal(t, metrics.ExpectedItems(), unmarshaled.ExpectedItems())
			assert.Equal(t, metrics.ItemsProcessed(), unmarshaled.ItemsProcessed())
			assert.Equal(t, metrics.ErrorDetails(), unmarshaled.ErrorDetails())
		})
	}
}
