package reliability

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

func TestIsCriticalEvent(t *testing.T) {
	tests := []struct {
		name      string
		eventType events.EventType
		want      bool
	}{
		// Critical events - scanning task terminal states.
		{
			name:      "TaskCompleted is critical",
			eventType: scanning.EventTypeTaskCompleted,
			want:      true,
		},
		{
			name:      "TaskFailed is critical",
			eventType: scanning.EventTypeTaskFailed,
			want:      true,
		},
		{
			name:      "TaskCancelled is critical",
			eventType: scanning.EventTypeTaskCancelled,
			want:      true,
		},

		// Critical events - scanner registration states.
		{
			name:      "ScannerRegistered is critical",
			eventType: scanning.EventTypeScannerRegistered,
			want:      true,
		},
		{
			name:      "ScannerDeregistered is critical",
			eventType: scanning.EventTypeScannerDeregistered,
			want:      true,
		},
		{
			name:      "ScannerStatusChanged is critical",
			eventType: scanning.EventTypeScannerStatusChanged,
			want:      true,
		},

		// Critical events - rules updates.
		{
			name:      "RulesUpdated is critical",
			eventType: rules.EventTypeRulesUpdated,
			want:      true,
		},
		{
			name:      "RulesPublished is critical",
			eventType: rules.EventTypeRulesPublished,
			want:      true,
		},

		// Non-critical events.
		{
			name:      "TaskProgressed is not critical",
			eventType: scanning.EventTypeTaskProgressed,
			want:      false,
		},
		{
			name:      "TaskJobMetric is not critical",
			eventType: scanning.EventTypeTaskJobMetric,
			want:      false,
		},
		{
			name:      "TaskHeartbeat is not critical",
			eventType: scanning.EventTypeTaskHeartbeat,
			want:      false,
		},

		// Default case - unknown event type.
		{
			name:      "Unknown event type is not critical",
			eventType: "unknown_event_type",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsCriticalEvent(tt.eventType))
		})
	}
}
