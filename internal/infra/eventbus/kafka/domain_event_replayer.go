package kafka

import (
	"context"
	"fmt"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

var _ events.DomainEventReplayer = (*DomainEventReplayer)(nil)

// DomainEventReplayer is responsible for replaying domain events from a specific position.
// It uses an event replayer to fetch events and a translator to convert domain positions
// into stream positions that the event replayer can understand.
// TODO: add metrics, logger, tracing, etc.
type DomainEventReplayer struct {
	eventReplayer events.EventReplayer
	translator    events.PositionTranslator
}

// NewDomainEventReplayer creates a new instance of DomainEventReplayer.
// It requires an event replayer to fetch events and a translator to convert domain positions
// into stream positions. This ensures the replayer can correctly interpret and replay events.
func NewDomainEventReplayer(replayer events.EventReplayer, translator events.PositionTranslator) *DomainEventReplayer {
	return &DomainEventReplayer{eventReplayer: replayer, translator: translator}
}

// ReplayFromPosition replays domain events starting from the specified position.
// It translates the domain position into a stream position using the translator and then
// fetches the events using the event replayer. Returns a channel of event envelopes or an error
// if the translation or replay fails.
func (r *DomainEventReplayer) ReplayFromPosition(
	ctx context.Context,
	pos events.DomainPosition,
) (<-chan events.EventEnvelope, error) {
	// Extract metadata from the domain position to prepare for translation.
	metadata := events.PositionMetadata{EntityType: pos.StreamType(), EntityID: pos.StreamID()}

	// Translate the domain position into a stream position.
	// This is necessary because the event replayer operates on stream positions.
	streamPos, err := r.translator.ToStreamPosition(metadata)
	if err != nil {
		return nil, fmt.Errorf("translating position: %w", err)
	}

	// Replay events from the translated stream position.
	return r.eventReplayer.ReplayEvents(ctx, streamPos)
}
