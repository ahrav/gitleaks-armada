package kafka

import "fmt"

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
		return fmt.Errorf("invalid partition: %d", p.Partition)
	}
	if p.Offset < 0 {
		return fmt.Errorf("invalid offset: %d", p.Offset)
	}
	return nil
}
