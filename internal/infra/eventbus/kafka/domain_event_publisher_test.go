package kafka

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// MockEventBus is a manual mock implementation of events.EventBus.
type MockEventBus struct {
	publishFunc func(ctx context.Context, event events.EventEnvelope, opts ...events.PublishOption) error
}

func (m *MockEventBus) Publish(ctx context.Context, event events.EventEnvelope, opts ...events.PublishOption) error {
	return m.publishFunc(ctx, event, opts...)
}

func (m *MockEventBus) Subscribe(ctx context.Context, eventTypes []events.EventType, handler events.HandlerFunc) error {
	return nil
}

func (m *MockEventBus) Close() error { return nil }

// MockDomainEventPublisherTranslator is a manual mock implementation of events.DomainEventTranslator.
type MockDomainEventPublisherTranslator struct {
	toStreamPositionFunc func(metadata events.PositionMetadata) (events.StreamPosition, error)
}

func (m *MockDomainEventPublisherTranslator) ToStreamPosition(metadata events.PositionMetadata) (events.StreamPosition, error) {
	if m.toStreamPositionFunc != nil {
		return m.toStreamPositionFunc(metadata)
	}
	return nil, nil
}

// MockDomainEvent is a manual mock implementation of events.DomainEvent.
type MockDomainEvent struct {
	eventType  events.EventType
	occurredAt time.Time
}

func (m *MockDomainEvent) EventType() events.EventType { return m.eventType }

func (m *MockDomainEvent) OccurredAt() time.Time { return m.occurredAt }

func TestDomainEventPublisher_PublishDomainEvent_Success(t *testing.T) {
	ctx := context.Background()
	event := &MockDomainEvent{
		eventType:  "test-event",
		occurredAt: time.Now(),
	}

	mockEventBus := &MockEventBus{
		publishFunc: func(ctx context.Context, evt events.EventEnvelope, opts ...events.PublishOption) error {
			assert.Equal(t, event.EventType(), evt.Type)
			assert.Equal(t, event.OccurredAt(), evt.Timestamp)
			assert.Equal(t, event, evt.Payload)
			return nil
		},
	}

	mockTranslator := &MockDomainEventPublisherTranslator{
		toStreamPositionFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return nil, nil
		},
	}

	publisher := NewDomainEventPublisher(mockEventBus, events.NewDomainEventTranslator(mockTranslator))
	err := publisher.PublishDomainEvent(ctx, event)
	assert.NoError(t, err)
}

func TestDomainEventPublisher_PublishDomainEvent_Error(t *testing.T) {
	ctx := context.Background()
	event := &MockDomainEvent{eventType: "test-event", occurredAt: time.Now()}

	mockEventBus := &MockEventBus{
		publishFunc: func(ctx context.Context, evt events.EventEnvelope, opts ...events.PublishOption) error {
			return errors.New("publish failed")
		},
	}

	mockTranslator := &MockDomainEventPublisherTranslator{
		toStreamPositionFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return nil, nil
		},
	}

	publisher := NewDomainEventPublisher(mockEventBus, events.NewDomainEventTranslator(mockTranslator))
	err := publisher.PublishDomainEvent(ctx, event)
	assert.Error(t, err)
	assert.Equal(t, "publish failed", err.Error())
}

func TestDomainEventPublisher_PublishDomainEvent_OptionsConversion(t *testing.T) {
	ctx := context.Background()
	event := &MockDomainEvent{eventType: "test-event", occurredAt: time.Now()}

	var receivedOpts []events.PublishOption
	mockEventBus := &MockEventBus{
		publishFunc: func(ctx context.Context, evt events.EventEnvelope, opts ...events.PublishOption) error {
			receivedOpts = opts
			return nil
		},
	}

	// Create a test option that actually sets something in PublishParams.
	testOption := func(params *events.PublishParams) { params.Key = "test-key" }

	mockTranslator := &MockDomainEventPublisherTranslator{
		toStreamPositionFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return nil, nil
		},
	}

	publisher := NewDomainEventPublisher(mockEventBus, events.NewDomainEventTranslator(mockTranslator))

	err := publisher.PublishDomainEvent(ctx, event, testOption)
	assert.NoError(t, err)

	assert.Equal(t, 1, len(receivedOpts), "EventBus should receive exactly one option")

	params := &events.PublishParams{}
	if len(receivedOpts) > 0 {
		receivedOpts[0](params)
		assert.Equal(t, "test-key", params.Key, "The key should be set in the params")
	}
}

func TestDomainEventPublisher_PublishDomainEvent_MultipleOptions(t *testing.T) {
	ctx := context.Background()
	event := &MockDomainEvent{eventType: "test-event", occurredAt: time.Now()}

	var receivedOpts []events.PublishOption
	mockEventBus := &MockEventBus{
		publishFunc: func(ctx context.Context, evt events.EventEnvelope, opts ...events.PublishOption) error {
			receivedOpts = opts
			return nil
		},
	}

	// Create multiple options.
	keyOption := func(params *events.PublishParams) { params.Key = "test-key" }
	headerOption := func(params *events.PublishParams) {
		params.Headers = map[string]string{"test-header": "test-value"}
	}

	mockTranslator := &MockDomainEventPublisherTranslator{
		toStreamPositionFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return nil, nil
		},
	}

	publisher := NewDomainEventPublisher(mockEventBus, events.NewDomainEventTranslator(mockTranslator))
	err := publisher.PublishDomainEvent(ctx, event, keyOption, headerOption)
	assert.NoError(t, err)

	params := &events.PublishParams{}
	for _, opt := range receivedOpts {
		opt(params)
	}
	assert.Equal(t, "test-key", params.Key)
	assert.Equal(t, "test-value", params.Headers["test-header"])
}

func TestDomainEventPublisher_PublishDomainEvent_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	event := &MockDomainEvent{eventType: "test-event", occurredAt: time.Now()}

	mockEventBus := &MockEventBus{
		publishFunc: func(ctx context.Context, evt events.EventEnvelope, opts ...events.PublishOption) error {
			return ctx.Err()
		},
	}

	mockTranslator := &MockDomainEventPublisherTranslator{
		toStreamPositionFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return nil, nil
		},
	}

	publisher := NewDomainEventPublisher(mockEventBus, events.NewDomainEventTranslator(mockTranslator))
	err := publisher.PublishDomainEvent(ctx, event)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestDomainEventPublisher_PublishDomainEvent_Concurrency(t *testing.T) {
	ctx := context.Background()
	event := &MockDomainEvent{eventType: "test-event", occurredAt: time.Now()}

	var publishCount int32
	mockEventBus := &MockEventBus{
		publishFunc: func(ctx context.Context, evt events.EventEnvelope, opts ...events.PublishOption) error {
			atomic.AddInt32(&publishCount, 1)
			return nil
		},
	}

	mockTranslator := &MockDomainEventPublisherTranslator{
		toStreamPositionFunc: func(metadata events.PositionMetadata) (events.StreamPosition, error) {
			return nil, nil
		},
	}

	publisher := NewDomainEventPublisher(mockEventBus, events.NewDomainEventTranslator(mockTranslator))

	var wg sync.WaitGroup
	numGoroutines := 10
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := publisher.PublishDomainEvent(ctx, event)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(numGoroutines), atomic.LoadInt32(&publishCount))
}
