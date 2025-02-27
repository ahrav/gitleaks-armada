package enumeration

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBatch(t *testing.T) {
	sessionID := uuid.New()
	expectedItems := 10
	checkpoint := &Checkpoint{}
	tp := &mockTimeProvider{current: time.Now()}

	batch := NewBatch(sessionID, expectedItems, checkpoint, WithTimeProvider(tp))

	assert.NotEmpty(t, batch.BatchID())
	assert.Equal(t, sessionID, batch.SessionID())
	assert.Equal(t, BatchStatusInProgress, batch.Status())
	assert.Equal(t, checkpoint, batch.Checkpoint())
	assert.NotNil(t, batch.Timeline())
	assert.NotNil(t, batch.Metrics())
}

func TestBatch_MarkSuccessful(t *testing.T) {
	tests := []struct {
		name           string
		initialStatus  BatchStatus
		itemsProcessed int
		expectedError  bool
	}{
		{
			name:           "successful transition from in progress",
			initialStatus:  BatchStatusInProgress,
			itemsProcessed: 10,
			expectedError:  false,
		},
		{
			name:           "invalid transition from succeeded",
			initialStatus:  BatchStatusSucceeded,
			itemsProcessed: 10,
			expectedError:  true,
		},
		{
			name:           "invalid transition from failed",
			initialStatus:  BatchStatusFailed,
			itemsProcessed: 10,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := &mockTimeProvider{current: time.Now()}
			batch := NewBatch(uuid.New(), 10, nil, WithTimeProvider(tp))
			batch.status = tt.initialStatus

			err := batch.MarkSuccessful(tt.itemsProcessed)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, BatchStatusSucceeded, batch.Status())
				assert.True(t, batch.Timeline().IsCompleted())
			}
		})
	}
}

func TestBatch_MarkFailed(t *testing.T) {
	tests := []struct {
		name          string
		initialStatus BatchStatus
		expectedError bool
	}{
		{
			name:          "successful transition from in progress",
			initialStatus: BatchStatusInProgress,
			expectedError: false,
		},
		{
			name:          "invalid transition from succeeded",
			initialStatus: BatchStatusSucceeded,
			expectedError: true,
		},
		{
			name:          "invalid transition from failed",
			initialStatus: BatchStatusFailed,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := &mockTimeProvider{current: time.Now()}
			batch := NewBatch(uuid.New(), 10, nil, WithTimeProvider(tp))
			batch.status = tt.initialStatus
			testErr := errors.New("test error")

			err := batch.MarkFailed(testErr)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, BatchStatusFailed, batch.Status())
				assert.True(t, batch.Timeline().IsCompleted())
			}
		})
	}
}

func TestBatch_JSON(t *testing.T) {
	tp := &mockTimeProvider{current: time.Now()}
	originalBatch := NewBatch(uuid.New(), 10, &Checkpoint{}, WithTimeProvider(tp))

	data, err := json.Marshal(originalBatch)
	require.NoError(t, err)

	var unmarshaledBatch Batch
	err = json.Unmarshal(data, &unmarshaledBatch)

	require.NoError(t, err)
	assert.Equal(t, originalBatch.BatchID(), unmarshaledBatch.BatchID())
	assert.Equal(t, originalBatch.SessionID(), unmarshaledBatch.SessionID())
	assert.Equal(t, originalBatch.Status(), unmarshaledBatch.Status())
	assert.Equal(t, originalBatch.Checkpoint(), unmarshaledBatch.Checkpoint())
}
