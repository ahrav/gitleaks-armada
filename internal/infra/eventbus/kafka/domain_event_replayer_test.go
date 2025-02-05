package kafka

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// MockEventReplayer is a manual mock implementation of events.EventReplayer.
type MockEventReplayer struct {
	replayFunc func(ctx context.Context, pos events.StreamPosition) (<-chan events.EventEnvelope, error)
	closeFunc  func() error
}

func (m *MockEventReplayer) ReplayEvents(ctx context.Context, pos events.StreamPosition) (<-chan events.EventEnvelope, error) {
	return m.replayFunc(ctx, pos)
}

func (m *MockEventReplayer) Close() error { return m.closeFunc() }

// MockDomainEventReplayerTranslator is a manual mock implementation of events.DomainEventTranslator.
type MockDomainEventReplayerTranslator struct {
	translateFunc func(metadata events.PositionMetadata) (events.StreamPosition, error)
}

func (m *MockDomainEventReplayerTranslator) ToStreamPosition(metadata events.PositionMetadata) (events.StreamPosition, error) {
	return m.translateFunc(metadata)
}

// MockStreamPosition is a manual mock implementation of events.StreamPosition.
type MockStreamPosition struct{}

func (m *MockStreamPosition) Identifier() string { return "mock-stream-position" }

func (m *MockStreamPosition) Validate() error { return nil }

// MockDomainPosition is a manual mock implementation of events.DomainPosition.
type MockDomainPosition struct {
	streamType events.StreamType
	streamID   string
}

func (m *MockDomainPosition) StreamType() events.StreamType { return m.streamType }

func (m *MockDomainPosition) StreamID() string { return m.streamID }

func TestDomainEventReplayer_ReplayFromPosition_Success(t *testing.T) {
	ctx := context.Background()
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}
	streamPos := new(MockStreamPosition)

	mockTranslator := &MockDomainEventReplayerTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			assert.Equal(t, events.StreamType("test"), metadata.EntityType)
			assert.Equal(t, "123", metadata.EntityID)
			return streamPos, nil
		},
	}

	eventChan := make(chan events.EventEnvelope, 1)
	eventChan <- events.EventEnvelope{}
	close(eventChan)
	mockReplayer := &MockEventReplayer{
		replayFunc: func(ctx context.Context, pos events.StreamPosition) (<-chan events.EventEnvelope, error) {
			return eventChan, nil
		},
	}

	replayer := NewDomainEventReplayer(mockReplayer, events.NewDomainEventTranslator(mockTranslator))

	resultChan, err := replayer.ReplayFromPosition(ctx, pos)
	assert.NoError(t, err)
	assert.NotNil(t, resultChan)
}

func TestDomainEventReplayer_ReplayFromPosition_TranslationError(t *testing.T) {
	ctx := context.Background()
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}
	mockTranslator := &MockDomainEventReplayerTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			assert.Equal(t, events.StreamType("test"), metadata.EntityType)
			assert.Equal(t, "123", metadata.EntityID)
			return nil, errors.New("translation failed")
		},
	}

	mockReplayer := &MockEventReplayer{
		replayFunc: func(ctx context.Context, pos events.StreamPosition) (<-chan events.EventEnvelope, error) {
			return nil, nil
		},
	}

	replayer := NewDomainEventReplayer(mockReplayer, events.NewDomainEventTranslator(mockTranslator))

	resultChan, err := replayer.ReplayFromPosition(ctx, pos)
	assert.Error(t, err)
	assert.Nil(t, resultChan)
}

func TestDomainEventReplayer_ReplayFromPosition_ReplayError(t *testing.T) {
	ctx := context.Background()
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}
	streamPos := new(MockStreamPosition)

	mockTranslator := &MockDomainEventReplayerTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return streamPos, nil
		},
	}

	mockReplayer := &MockEventReplayer{
		replayFunc: func(ctx context.Context, pos events.StreamPosition) (<-chan events.EventEnvelope, error) {
			return nil, errors.New("replay failed")
		},
	}

	replayer := NewDomainEventReplayer(mockReplayer, events.NewDomainEventTranslator(mockTranslator))

	resultChan, err := replayer.ReplayFromPosition(ctx, pos)
	assert.Error(t, err)
	assert.Nil(t, resultChan)
}

func TestDomainEventReplayer_ReplayFromPosition_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}
	streamPos := new(MockStreamPosition)

	mockTranslator := &MockDomainEventReplayerTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return streamPos, nil
		},
	}

	mockReplayer := &MockEventReplayer{
		replayFunc: func(ctx context.Context, pos events.StreamPosition) (<-chan events.EventEnvelope, error) {
			cancel() // Simulate context cancellation
			return nil, ctx.Err()
		},
	}

	replayer := NewDomainEventReplayer(mockReplayer, events.NewDomainEventTranslator(mockTranslator))

	resultChan, err := replayer.ReplayFromPosition(ctx, pos)
	assert.Error(t, err)
	assert.Nil(t, resultChan)
	assert.Equal(t, context.Canceled, err)
}

func TestDomainEventReplayer_ReplayFromPosition_ChannelClosure(t *testing.T) {
	ctx := context.Background()
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}
	streamPos := new(MockStreamPosition)

	mockTranslator := &MockDomainEventReplayerTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return streamPos, nil
		},
	}

	eventChan := make(chan events.EventEnvelope)
	close(eventChan) // Close the channel immediately
	mockReplayer := &MockEventReplayer{
		replayFunc: func(ctx context.Context, pos events.StreamPosition) (<-chan events.EventEnvelope, error) {
			return eventChan, nil
		},
	}

	replayer := NewDomainEventReplayer(mockReplayer, events.NewDomainEventTranslator(mockTranslator))

	resultChan, err := replayer.ReplayFromPosition(ctx, pos)
	assert.NoError(t, err)
	assert.NotNil(t, resultChan)
	_, ok := <-resultChan
	assert.False(t, ok) // Verify the channel is closed
}

func TestDomainEventReplayer_ReplayFromPosition_Concurrency(t *testing.T) {
	ctx := context.Background()
	pos := &MockDomainPosition{streamType: "test", streamID: "123"}
	streamPos := new(MockStreamPosition)

	mockTranslator := &MockDomainEventReplayerTranslator{
		translateFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return streamPos, nil
		},
	}

	eventChan := make(chan events.EventEnvelope, 1)
	eventChan <- events.EventEnvelope{}
	close(eventChan)
	mockReplayer := &MockEventReplayer{
		replayFunc: func(ctx context.Context, pos events.StreamPosition) (<-chan events.EventEnvelope, error) {
			return eventChan, nil
		},
	}

	replayer := NewDomainEventReplayer(mockReplayer, events.NewDomainEventTranslator(mockTranslator))

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resultChan, err := replayer.ReplayFromPosition(ctx, pos)
			assert.NoError(t, err)
			assert.NotNil(t, resultChan)
		}()
	}
	wg.Wait()
}
