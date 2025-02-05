package kafka

import (
	"context"
	"fmt"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// DomainOffsetCommitter implements OffsetCommitter (the domain interface)
// It uses a PositionTranslator to convert a DomainPosition to a StreamPosition,
// then delegates the commit to the underlying KafkaOffsetCommitter.
// TODO: add metrics, logger, tracing, etc.
type DomainOffsetCommitter struct {
	translator events.PositionTranslator // translates DomainPosition → StreamPosition
	commiter   *KafkaOffsetCommitter
}

func NewDomainOffsetCommitter(translator events.PositionTranslator, commiter *KafkaOffsetCommitter) *DomainOffsetCommitter {
	return &DomainOffsetCommitter{translator: translator, commiter: commiter}
}

// CommitPosition translates the DomainPosition and then commits it.
func (d *DomainOffsetCommitter) CommitPosition(ctx context.Context, pos events.DomainPosition) error {
	metadata := events.PositionMetadata{
		EntityType: pos.StreamType(),
		EntityID:   pos.StreamID(),
	}
	streamPos, err := d.translator.ToStreamPosition(metadata)
	if err != nil {
		return fmt.Errorf("failed to translate domain position: %w", err)
	}
	if err := streamPos.Validate(); err != nil {
		return fmt.Errorf("invalid stream position: %w", err)
	}
	return d.commiter.CommitPosition(ctx, streamPos)
}
