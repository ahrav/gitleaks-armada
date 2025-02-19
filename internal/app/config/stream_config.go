package config

import (
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
)

// NewTopicMapper creates a mapper with all known stream type to topic mappings.
// It is used to map stream types to Kafka topics.
func NewTopicMapper(cfg *kafka.EventBusConfig) kafka.TopicMapper {
	return kafka.NewStaticTopicMapper(map[events.StreamType]string{
		scanning.JobLifecycleStreamType: cfg.JobLifecycleTopic,
		// TODO: Add all the other topics which we need to replay events from or
		// commit offsets for.
	})
}
