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

// ErrInvalidPartition is an error type for invalid partition values.
type ErrInvalidPartition struct{ Partition string }

func (e ErrInvalidPartition) Error() string {
	return fmt.Sprintf("invalid partition: %s", e.Partition)
}

// ErrInvalidOffset is an error type for invalid offset values.
type ErrInvalidOffset struct{ Offset string }

func (e ErrInvalidOffset) Error() string {
	return fmt.Sprintf("invalid offset: %s", e.Offset)
}

var _ events.StreamPosition = (*Position)(nil)

// Position represents a specific location in a Kafka partition,
// identified by a partition number and an offset.
// It is used to specify where to start replaying events in a Kafka topic.
type Position struct {
	Partition int32
	Offset    int64
}

// Identifier returns a string representation of the Position in the format "partition:offset".
func (p Position) Identifier() string { return fmt.Sprintf("%d:%d", p.Partition, p.Offset) }

// Validate checks if the Position is valid.
// A valid Position has a non-negative partition and offset.
// Returns an error if the Position is invalid.
func (p Position) Validate() error {
	if p.Partition < 0 {
		return ErrInvalidPartition{Partition: fmt.Sprintf("%d", p.Partition)}
	}
	if p.Offset < 0 {
		return ErrInvalidOffset{Offset: fmt.Sprintf("%d", p.Offset)}
	}
	return nil
}

// ErrInvalidPositionFormat is an error type for invalid job metrics position formats.
type ErrInvalidPositionFormat struct{ EntityID string }

func (e ErrInvalidPositionFormat) Error() string {
	return fmt.Sprintf("invalid job metrics position format: %s", e.EntityID)
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
		return Position{}, ErrInvalidPositionFormat{EntityID: entityID}
	}

	partition, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil {
		return Position{}, ErrInvalidPartition{Partition: parts[0]}
	}

	offset, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return Position{}, ErrInvalidOffset{Offset: parts[1]}
	}

	return Position{
		Partition: int32(partition),
		Offset:    offset,
	}, nil
}

// ErrNoTranslationRule is an error type for when no translation rule exists for an entity type.
type ErrNoTranslationRule struct{ EntityType events.StreamType }

func (e ErrNoTranslationRule) Error() string {
	return fmt.Sprintf("no translation rule for entity type: %s", e.EntityType)
}

var _ events.PositionTranslator = (*KafkaPositionTranslator)(nil)

// KafkaPositionTranslator is responsible for translating domain positions into Kafka stream positions.
// It uses a set of rules, each associated with a specific entity type, to perform the translation.
// If no rule exists for a given entity type, an error is returned.
type KafkaPositionTranslator struct {
	rules map[events.StreamType]RuleTranslator
}

// NewKafkaPositionTranslator initializes a new KafkaPositionTranslator with default rules.
// Currently, it includes a rule for translating job metrics entity IDs.
func NewKafkaPositionTranslator() *KafkaPositionTranslator {
	return &KafkaPositionTranslator{
		rules: map[events.StreamType]RuleTranslator{
			scanning.JobMetricsEntityType: JobMetricsTranslationRule{},
		},
	}
}

// ToStreamPosition translates a domain position into a Kafka stream position using the appropriate rule.
// It returns an error if no translation rule exists for the given entity type.
func (t *KafkaPositionTranslator) ToStreamPosition(metadata events.PositionMetadata) (events.StreamPosition, error) {
	rule, exists := t.rules[metadata.EntityType]
	if !exists {
		return nil, ErrNoTranslationRule{EntityType: metadata.EntityType}
	}

	return rule.Translate(metadata.EntityID)
}
