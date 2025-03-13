// Package reliability provides utilities for determining the criticality of events
// within the event messaging system. Event criticality is a classification that helps
// establish appropriate handling, persistence, and delivery guarantees for different
// types of events.
package reliability

import (
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// IsCriticalEvent determines if an event type represents a message that
// requires acknowledgment in transport mechanisms that don't have
// built-in durability guarantees like Kafka.
//
// Critical events are usually terminal state changes or final results that:
// 1. Won't be naturally retransmitted by subsequent messages
// 2. Would result in data loss or inconsistency if not processed
// 3. Represent important state transitions in the system
func IsCriticalEvent(eventType events.EventType) bool {
	switch eventType {
	case scanning.EventTypeTaskCompleted,
		scanning.EventTypeTaskFailed,
		scanning.EventTypeTaskCancelled:
		return true

	case scanning.EventTypeScannerRegistered,
		scanning.EventTypeScannerDeregistered,
		scanning.EventTypeScannerStatusChanged:
		return true

	case rules.EventTypeRulesUpdated, rules.EventTypeRulesRequested:
		return true

	case scanning.EventTypeTaskProgressed,
		scanning.EventTypeTaskJobMetric,
		scanning.EventTypeTaskHeartbeat:
		return false

	default:
		return false
	}
}
