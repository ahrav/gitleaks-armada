package events

// DomainEventTranslator centralizes the translation of domain-level constructs into
// event bus-specific constructs. It avoids duplication of translation logic across
// components like DomainEventPublisher and DomainEventReplayer, ensuring consistency
// and maintainability.
type DomainEventTranslator struct{ positionTranslator PositionTranslator }

// NewDomainEventTranslator creates a new DomainEventTranslator with the provided
// PositionTranslator. This ensures that all required dependencies are properly
// initialized and makes the component easier to test and manage.
func NewDomainEventTranslator(positionTranslator PositionTranslator) *DomainEventTranslator {
	return &DomainEventTranslator{positionTranslator: positionTranslator}
}

// ToStreamPosition translates domain-level position metadata into a messaging
// system-specific stream position. This is necessary because the event bus operates
// on stream positions, while the domain layer works with abstract domain positions.
func (t *DomainEventTranslator) ToStreamPosition(metadata PositionMetadata) (StreamPosition, error) {
	return t.positionTranslator.ToStreamPosition(metadata)
}

// ConvertDomainOptions transforms domain-level publishing options into event bus
// options. This allows the domain layer to configure event publishing (e.g., routing
// keys, headers) without being tightly coupled to the event bus implementation.
func (t *DomainEventTranslator) ConvertDomainOptions(domainOpts []PublishOption) []PublishOption {
	dp := PublishParams{}
	for _, dOpt := range domainOpts {
		dOpt(&dp)
	}

	var eventOpts []PublishOption
	if dp.Key != "" {
		eventOpts = append(eventOpts, WithKey(dp.Key))
	}
	if len(dp.Headers) > 0 {
		eventOpts = append(eventOpts, WithHeaders(dp.Headers))
	}

	return eventOpts
}
