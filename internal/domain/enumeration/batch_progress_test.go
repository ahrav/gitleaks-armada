package enumeration

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewSuccessfulBatchProgress(t *testing.T) {
	cp := NewTemporaryCheckpoint("test-target", nil)
	bp := NewSuccessfulBatchProgress(42, cp)

	require.NotEmpty(t, bp.BatchID())
	require.Equal(t, BatchStatusSucceeded, bp.Status())
	require.Equal(t, 42, bp.ItemsProcessed())
	require.Equal(t, cp, bp.Checkpoint())
	require.WithinDuration(t, time.Now(), bp.StartedAt(), 2*time.Second)
	require.WithinDuration(t, time.Now(), bp.CompletedAt(), 2*time.Second)
}

func TestNewFailedBatchProgress(t *testing.T) {
	cp := NewTemporaryCheckpoint("test-target", nil)
	bp := NewFailedBatchProgress(errors.New("some error"), cp)

	require.NotEmpty(t, bp.BatchID())
	require.Equal(t, BatchStatusFailed, bp.Status())
	require.Equal(t, 0, bp.ItemsProcessed(), "Failed batch typically has 0 items processed")
	require.Equal(t, "some error", bp.ErrorDetails())
	require.Equal(t, cp, bp.Checkpoint())
}

func TestBatchProgressJSONRoundTrip(t *testing.T) {
	original := NewSuccessfulBatchProgress(100, nil)

	bytesData, err := json.Marshal(&original)
	require.NoError(t, err)

	var bp BatchProgress
	require.NoError(t, json.Unmarshal(bytesData, &bp))

	require.Equal(t, original.BatchID(), bp.BatchID())
	require.Equal(t, original.Status(), bp.Status())
	require.Equal(t, original.ItemsProcessed(), bp.ItemsProcessed())
	require.WithinDuration(t, original.StartedAt(), bp.StartedAt(), 1*time.Microsecond)
	require.WithinDuration(t, original.CompletedAt(), bp.CompletedAt(), 1*time.Microsecond)
}

func TestNewPendingBatchProgress(t *testing.T) {
	cp := NewTemporaryCheckpoint("test-target", nil)
	expectedItems := 42
	bp := NewPendingBatchProgress(expectedItems, cp)

	require.NotEmpty(t, bp.BatchID())
	require.Equal(t, BatchStatusPending, bp.Status())
	require.Equal(t, 0, bp.ItemsProcessed(), "Pending batch should have 0 items processed")
	require.Equal(t, cp, bp.Checkpoint())
	require.WithinDuration(t, time.Now(), bp.StartedAt(), 2*time.Second)
	require.True(t, bp.CompletedAt().IsZero(), "Pending batch should not have completion time")
	require.Empty(t, bp.ErrorDetails(), "Pending batch should not have error details")
}
