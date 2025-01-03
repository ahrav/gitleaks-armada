package rules

import (
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

const (
	EventTypeRuleUpdated events.EventType = "RuleUpdated"
)

// --------------------------
// 1. RuleUpdatedEvent
// --------------------------

// RuleUpdatedEvent is the strongly typed domain event indicating that a Gitleaks rule was added or updated.
type RuleUpdatedEvent struct {
	occurredAt time.Time
	Rule       GitleaksRuleMessage
}

// NewRuleUpdatedEvent creates a new RuleUpdatedEvent, setting the occurrence time to now.
func NewRuleUpdatedEvent(msg GitleaksRuleMessage) RuleUpdatedEvent {
	return RuleUpdatedEvent{
		occurredAt: time.Now(),
		Rule:       msg,
	}
}

// EventType satisfies the events.DomainEvent interface,
// returning a constant that identifies this event in the system.
func (e RuleUpdatedEvent) EventType() events.EventType { return EventTypeRuleUpdated }

// OccurredAt satisfies the events.DomainEvent interface,
// returning when this rule update event occurred.
func (e RuleUpdatedEvent) OccurredAt() time.Time { return e.occurredAt }
