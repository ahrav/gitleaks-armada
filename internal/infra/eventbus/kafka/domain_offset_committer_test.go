package kafka

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// MockPositionTranslator is a manual mock implementation of events.PositionTranslator
type MockPositionTranslator struct {
	translateFunc func(metadata events.PositionMetadata) (events.StreamPosition, error)
}

func (m *MockPositionTranslator) ToStreamPosition(metadata events.PositionMetadata) (events.StreamPosition, error) {
	return m.translateFunc(metadata)
}

// MockKafkaOffsetCommitter is a manual mock implementation of KafkaOffsetCommitter
type MockKafkaOffsetCommitter struct {
	commitFunc func(ctx context.Context, pos events.StreamPosition) error
}

func (m *MockKafkaOffsetCommitter) CommitPosition(ctx context.Context, pos events.StreamPosition) error {
	return m.commitFunc(ctx, pos)
}

func (m *MockKafkaOffsetCommitter) Close() error { return nil }

func TestDomainOffsetCommitter_CommitPosition_Success(t *testing.T) {
	ctx := context.Background()
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}
	streamPos := new(MockStreamPosition)

	mockTranslator := &MockPositionTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			assert.Equal(t, events.StreamType("test"), metadata.EntityType)
			assert.Equal(t, "123", metadata.EntityID)
			return streamPos, nil
		},
	}

	mockCommitter := &MockKafkaOffsetCommitter{
		commitFunc: func(ctx context.Context, pos events.StreamPosition) error {
			assert.Equal(t, streamPos, pos)
			return nil
		},
	}

	committer := NewDomainOffsetCommitter(mockTranslator, mockCommitter)

	err := committer.CommitPosition(ctx, pos)
	assert.NoError(t, err)
}

func TestDomainOffsetCommitter_CommitPosition_TranslationError(t *testing.T) {
	ctx := context.Background()
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}

	mockTranslator := &MockPositionTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return nil, errors.New("translation failed")
		},
	}

	mockCommitter := &MockKafkaOffsetCommitter{
		commitFunc: func(ctx context.Context, pos events.StreamPosition) error {
			t.Fatal("commit should not be called")
			return nil
		},
	}

	committer := NewDomainOffsetCommitter(mockTranslator, mockCommitter)

	err := committer.CommitPosition(ctx, pos)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to translate domain position")
}

func TestDomainOffsetCommitter_CommitPosition_ValidationError(t *testing.T) {
	ctx := context.Background()
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}

	mockTranslator := &MockPositionTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return nil, errors.New("validation failed")
		},
	}

	mockCommitter := &MockKafkaOffsetCommitter{
		commitFunc: func(ctx context.Context, pos events.StreamPosition) error {
			t.Fatal("commit should not be called")
			return nil
		},
	}

	committer := NewDomainOffsetCommitter(mockTranslator, mockCommitter)

	err := committer.CommitPosition(ctx, pos)
	assert.Error(t, err)
}

func TestDomainOffsetCommitter_CommitPosition_CommitError(t *testing.T) {
	ctx := context.Background()
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}
	streamPos := new(MockStreamPosition)

	mockTranslator := &MockPositionTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return streamPos, nil
		},
	}

	mockCommitter := &MockKafkaOffsetCommitter{
		commitFunc: func(ctx context.Context, pos events.StreamPosition) error {
			return errors.New("commit failed")
		},
	}

	committer := NewDomainOffsetCommitter(mockTranslator, mockCommitter)

	err := committer.CommitPosition(ctx, pos)
	assert.Error(t, err)
}

func TestDomainOffsetCommitter_CommitPosition_Concurrency(t *testing.T) {
	ctx := context.Background()
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}
	streamPos := new(MockStreamPosition)

	var commitCount int32

	mockTranslator := &MockPositionTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			assert.Equal(t, events.StreamType("test"), metadata.EntityType)
			assert.Equal(t, "123", metadata.EntityID)
			return streamPos, nil
		},
	}

	mockCommitter := &MockKafkaOffsetCommitter{
		commitFunc: func(ctx context.Context, pos events.StreamPosition) error {
			atomic.AddInt32(&commitCount, 1)
			return nil
		},
	}

	committer := NewDomainOffsetCommitter(mockTranslator, mockCommitter)

	var wg sync.WaitGroup
	numGoroutines := 10
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := committer.CommitPosition(ctx, pos)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(numGoroutines), atomic.LoadInt32(&commitCount))
}
