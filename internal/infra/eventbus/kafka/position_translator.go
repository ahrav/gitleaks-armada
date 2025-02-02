package kafka

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// RuleTranslator defines an interface for translating domain entity IDs into Kafka positions.
// Implementations of this interface are responsible for parsing and converting entity-specific
// identifiers into Kafka partition and offset values.
type RuleTranslator interface {
	// Translate converts a domain entity ID to a Kafka position.
	Translate(entityID string) (Position, error)
}

var _ RuleTranslator = (*JobMetricsTranslationRule)(nil)

// JobMetricsTranslationRule implements RuleTranslator for job metrics entity IDs.
// It expects entity IDs in the format "partition:offset" and parses them into Kafka positions.
type JobMetricsTranslationRule struct{}

// Translate translates a job metrics entity ID into a Kafka position.
// It expects entity IDs in the format "partition:offset" and parses them into Kafka positions.
func (r JobMetricsTranslationRule) Translate(entityID string) (Position, error) {
	parts := strings.Split(entityID, ":")
	if len(parts) != 2 {
		return Position{}, fmt.Errorf("invalid job metrics position format: %s", entityID)
	}

	partition, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil {
		return Position{}, fmt.Errorf("invalid partition: %w", err)
	}

	offset, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return Position{}, fmt.Errorf("invalid offset: %w", err)
	}

	return Position{
		Partition: int32(partition),
		Offset:    offset,
	}, nil
}

var _ events.PositionTranslator = (*KafkaPositionTranslator)(nil)

// KafkaPositionTranslator is responsible for translating domain positions into Kafka stream positions.
// It uses a set of rules, each associated with a specific entity type, to perform the translation.
// If no rule exists for a given entity type, an error is returned.
type KafkaPositionTranslator struct {
	rules map[events.EntityType]RuleTranslator
}

// NewKafkaPositionTranslator initializes a new KafkaPositionTranslator with default rules.
// Currently, it includes a rule for translating job metrics entity IDs.
func NewKafkaPositionTranslator() *KafkaPositionTranslator {
	return &KafkaPositionTranslator{
		rules: map[events.EntityType]RuleTranslator{
			scanning.JobMetricsEntityType: JobMetricsTranslationRule{},
		},
	}
}

// ToStreamPosition translates a domain position into a Kafka stream position using the appropriate rule.
// It returns an error if no translation rule exists for the given entity type.
func (t *KafkaPositionTranslator) ToStreamPosition(metadata events.PositionMetadata) (events.StreamPosition, error) {
	rule, exists := t.rules[metadata.EntityType]
	if !exists {
		return nil, fmt.Errorf("no translation rule for entity type: %s", metadata.EntityType)
	}

	return rule.Translate(metadata.EntityID)
}
