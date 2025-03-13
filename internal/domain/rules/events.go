package rules

import (
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

const (
	EventTypeRulesUpdated   events.EventType = "RulesUpdated"
	EventTypeRulesRequested events.EventType = "RulesRequested"
	EventTypeRulesPublished events.EventType = "RulesPublished"
)

// RuleUpdatedEvent is the strongly typed domain event indicating that a Gitleaks rule was added or updated.
type RuleUpdatedEvent struct {
	occurredAt time.Time
	Rule       GitleaksRuleMessage
}

// NewRuleUpdatedEvent creates a new RuleUpdatedEvent, setting the occurrence time to now.
func NewRuleUpdatedEvent(msg GitleaksRuleMessage) RuleUpdatedEvent {
	return RuleUpdatedEvent{occurredAt: time.Now(), Rule: msg}
}

// EventType satisfies the events.DomainEvent interface,
// returning a constant that identifies this event in the system.
func (e RuleUpdatedEvent) EventType() events.EventType { return EventTypeRulesUpdated }

// OccurredAt satisfies the events.DomainEvent interface,
// returning when this rule update event occurred.
func (e RuleUpdatedEvent) OccurredAt() time.Time { return e.occurredAt }

// RuleRequestedEvent signals that rules should be published
type RuleRequestedEvent struct{ occurredAt time.Time }

func NewRuleRequestedEvent() RuleRequestedEvent { return RuleRequestedEvent{occurredAt: time.Now()} }

func (e RuleRequestedEvent) EventType() events.EventType { return EventTypeRulesRequested }
func (e RuleRequestedEvent) OccurredAt() time.Time       { return e.occurredAt }

// RulePublishingCompletedEvent signals that all rules have been published
type RulePublishingCompletedEvent struct{ occurredAt time.Time }

func NewRulePublishingCompletedEvent() RulePublishingCompletedEvent {
	return RulePublishingCompletedEvent{occurredAt: time.Now()}
}

func (e RulePublishingCompletedEvent) EventType() events.EventType { return EventTypeRulesPublished }
func (e RulePublishingCompletedEvent) OccurredAt() time.Time       { return e.occurredAt }
