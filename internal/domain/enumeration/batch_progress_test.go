package enumeration_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
)

func TestNewSuccessfulBatchProgress(t *testing.T) {
	cp := enumeration.NewTemporaryCheckpoint("test-target", nil)
	bp := enumeration.NewSuccessfulBatchProgress(42, cp)

	require.NotEmpty(t, bp.BatchID())
	require.Equal(t, enumeration.BatchStatusSucceeded, bp.Status())
	require.Equal(t, 42, bp.ItemsProcessed())
	require.Equal(t, cp, bp.Checkpoint())
	require.WithinDuration(t, time.Now(), bp.StartedAt(), 2*time.Second)
	require.WithinDuration(t, time.Now(), bp.CompletedAt(), 2*time.Second)
}

func TestNewFailedBatchProgress(t *testing.T) {
	cp := enumeration.NewTemporaryCheckpoint("test-target", nil)
	bp := enumeration.NewFailedBatchProgress(errors.New("some error"), cp)

	require.NotEmpty(t, bp.BatchID())
	require.Equal(t, enumeration.BatchStatusFailed, bp.Status())
	require.Equal(t, 0, bp.ItemsProcessed(), "Failed batch typically has 0 items processed")
	require.Equal(t, "some error", bp.ErrorDetails())
	require.Equal(t, cp, bp.Checkpoint())
}

func TestBatchProgressJSONRoundTrip(t *testing.T) {
	original := enumeration.NewSuccessfulBatchProgress(100, nil)

	bytesData, err := json.Marshal(&original)
	require.NoError(t, err)

	var bp enumeration.BatchProgress
	require.NoError(t, json.Unmarshal(bytesData, &bp))

	require.Equal(t, original.BatchID(), bp.BatchID())
	require.Equal(t, original.Status(), bp.Status())
	require.Equal(t, original.ItemsProcessed(), bp.ItemsProcessed())
	require.WithinDuration(t, original.StartedAt(), bp.StartedAt(), 1*time.Microsecond)
	require.WithinDuration(t, original.CompletedAt(), bp.CompletedAt(), 1*time.Microsecond)
}
