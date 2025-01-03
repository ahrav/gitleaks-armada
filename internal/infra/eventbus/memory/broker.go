// Package memory provides an in-memory implementation of the messaging system.
// It offers a lightweight, non-persistent message broker suitable for testing
// and development environments where durability is not required.
package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/task"
	"github.com/ahrav/gitleaks-armada/pkg/domain"
)

type handlerList[T any] []func(T) error

// Broker provides an in-memory implementation of the messaging.Broker interface.
// It enables decoupled communication between components through message passing,
// making it useful for testing and development environments where persistence
// is not required.
type Broker struct {
	mu sync.RWMutex

	taskHandlers     handlerList[task.Task]
	resultHandlers   handlerList[domain.ScanResult]
	progressHandlers handlerList[domain.ScanProgress]
	ruleHandlers     handlerList[rules.GitleaksRuleMessage]
}

// NewBroker creates and initializes a new in-memory message broker with empty
// handler slices for each message type.
func NewBroker() *Broker {
	return &Broker{
		taskHandlers:     make(handlerList[task.Task], 0),
		resultHandlers:   make(handlerList[domain.ScanResult], 0),
		progressHandlers: make(handlerList[domain.ScanProgress], 0),
		ruleHandlers:     make(handlerList[rules.GitleaksRuleMessage], 0),
	}
}

// subscribe is a generic helper function for handling all subscription types.
func subscribe[T any](ctx context.Context, mu *sync.RWMutex, handlers *handlerList[T], handler func(T) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if handler == nil {
		return errors.New("handler cannot be nil")
	}

	mu.Lock()
	handlerIndex := len(*handlers)
	*handlers = append(*handlers, handler)
	mu.Unlock()

	go func() {
		<-ctx.Done()
		mu.Lock()
		defer mu.Unlock()
		// Remove the handler at the stored index if it's still valid.
		if handlerIndex < len(*handlers) {
			*handlers = append((*handlers)[:handlerIndex], (*handlers)[handlerIndex+1:]...)
		}
	}()

	return nil
}

// publish is a generic helper function for handling all publish types.
func publish[T any](ctx context.Context, mu *sync.RWMutex, handlers handlerList[T], msg T) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	mu.RLock()
	// Create a copy of handlers to avoid holding the lock while executing them.
	handlersCopy := make([]func(T) error, len(handlers))
	copy(handlersCopy, handlers)
	mu.RUnlock()

	for _, handler := range handlersCopy {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := handler(msg); err != nil {
			return err
		}
	}
	return nil
}

// PublishTask broadcasts a task to all subscribed handlers, stopping at the first error.
// The handlers are copied before iteration to prevent deadlocks and ensure consistency.
func (b *Broker) PublishTask(ctx context.Context, task task.Task) error {
	return publish(ctx, &b.mu, b.taskHandlers, task)
}

// PublishTasks publishes multiple tasks sequentially to all subscribed handlers.
// It stops at the first error encountered during publishing.
func (b *Broker) PublishTasks(ctx context.Context, tasks []task.Task) error {
	for _, task := range tasks {
		if err := b.PublishTask(ctx, task); err != nil {
			return err
		}
	}
	return nil
}

// SubscribeTasks registers a new handler function for processing tasks.
// Multiple handlers can be registered and will all receive published tasks.
func (b *Broker) SubscribeTasks(ctx context.Context, handler func(task.Task) error) error {
	return subscribe(ctx, &b.mu, &b.taskHandlers, handler)
}

// PublishResult broadcasts a scan result to all subscribed handlers.
// The handlers are copied before iteration to prevent deadlocks and ensure consistency.
func (b *Broker) PublishResult(ctx context.Context, result domain.ScanResult) error {
	return publish(ctx, &b.mu, b.resultHandlers, result)
}

// SubscribeResults registers a new handler function for processing scan results.
// Multiple handlers can be registered and will all receive published results.
func (b *Broker) SubscribeResults(ctx context.Context, handler func(domain.ScanResult) error) error {
	return subscribe(ctx, &b.mu, &b.resultHandlers, handler)
}

// PublishProgress broadcasts scan progress updates to all subscribed handlers.
// The handlers are copied before iteration to prevent deadlocks and ensure consistency.
func (b *Broker) PublishProgress(ctx context.Context, progress domain.ScanProgress) error {
	return publish(ctx, &b.mu, b.progressHandlers, progress)
}

// SubscribeProgress registers a new handler function for processing scan progress updates.
// Multiple handlers can be registered and will all receive published progress updates.
func (b *Broker) SubscribeProgress(ctx context.Context, handler func(domain.ScanProgress) error) error {
	return subscribe(ctx, &b.mu, &b.progressHandlers, handler)
}

// PublishRules broadcasts Gitleaks rule sets to all subscribed handlers.
// The handlers are copied before iteration to prevent deadlocks and ensure consistency.
func (b *Broker) PublishRules(ctx context.Context, rules rules.GitleaksRuleMessage) error {
	return publish(ctx, &b.mu, b.ruleHandlers, rules)
}

// SubscribeRules registers a new handler function for processing Gitleaks rule sets.
// Multiple handlers can be registered and will all receive published rule sets.
func (b *Broker) SubscribeRules(ctx context.Context, handler func(rules.GitleaksRuleMessage) error) error {
	return subscribe(ctx, &b.mu, &b.ruleHandlers, handler)
}
