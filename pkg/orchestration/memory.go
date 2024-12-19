package orchestration

import (
	"fmt"
)

// InMemoryQueue is a simple WorkQueue...
type InMemoryQueue struct {
	// ... fields for a queue
}

// Implement WorkQueue methods for InMemoryQueue.
func (q *InMemoryQueue) Enqueue(chunk Chunk) error { return nil }
func (q *InMemoryQueue) Dequeue() (Chunk, error) {
	return Chunk{}, fmt.Errorf("empty")
}
func (q *InMemoryQueue) Acknowledge(chunkID string) error { return nil }
