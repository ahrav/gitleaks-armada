package orchestration

// WorkQueue manages the distribution of work chunks to workers.
type WorkQueue interface {
	Enqueue(chunk Chunk) error
	Dequeue() (Chunk, error)
	Acknowledge(chunkID string) error
}
