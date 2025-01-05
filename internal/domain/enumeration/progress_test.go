package enumeration_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
)

func TestReconstructProgress(t *testing.T) {
	now := time.Now()
	progress := enumeration.ReconstructProgress(
		now.Add(-10*time.Minute),
		now,
		100,
		50,
		2,
		5,
		nil, // no batches
	)
	require.Equal(t, 100, progress.ItemsFound())
	require.Equal(t, 50, progress.ItemsProcessed())
	require.Equal(t, 2, progress.FailedBatches())
	require.Equal(t, 5, progress.TotalBatches())
	require.WithinDuration(t, now.Add(-10*time.Minute), progress.StartedAt(), 1*time.Microsecond)
	require.WithinDuration(t, now, progress.LastUpdate(), 1*time.Microsecond)
}

func TestProgressJSONMarshaling(t *testing.T) {
	p := enumeration.ReconstructProgress(
		time.Now().Add(-5*time.Hour),
		time.Now(),
		200,
		180,
		3,
		7,
		nil,
	)

	data, err := json.Marshal(p)
	require.NoError(t, err)

	var p2 enumeration.Progress
	require.NoError(t, json.Unmarshal(data, &p2))

	require.Equal(t, p.ItemsFound(), p2.ItemsFound())
	require.Equal(t, p.ItemsProcessed(), p2.ItemsProcessed())
	require.Equal(t, p.FailedBatches(), p2.FailedBatches())
	require.Equal(t, p.TotalBatches(), p2.TotalBatches())
	require.WithinDuration(t, p.StartedAt(), p2.StartedAt(), 1*time.Microsecond)
	require.WithinDuration(t, p.LastUpdate(), p2.LastUpdate(), 1*time.Microsecond)
}
