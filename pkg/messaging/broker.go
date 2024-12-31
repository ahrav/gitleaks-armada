package messaging

import (
	"context"

	"github.com/ahrav/gitleaks-armada/pkg/messaging/types"
)

// Broker handles task distribution and result collection via message queue.
type Broker interface {
	// PublishTask publishes a task for workers to process.
	PublishTask(ctx context.Context, task types.Task) error
	// PublishTasks publishes multiple tasks in a batch.
	PublishTasks(ctx context.Context, tasks []types.Task) error
	// SubscribeTasks listens for new tasks to be processed by workers.
	SubscribeTasks(ctx context.Context, handler func(context.Context, types.Task) error) error

	// PublishResult publishes the findings and status from a completed scan task.
	PublishResult(ctx context.Context, result types.ScanResult) error
	// SubscribeResults listens for completed scan results to be collected by orchestrator.
	SubscribeResults(ctx context.Context, handler func(context.Context, types.ScanResult) error) error

	// PublishProgress publishes progress updates for a scan task.
	PublishProgress(ctx context.Context, progress types.ScanProgress) error
	// SubscribeProgress listens for progress updates from ongoing scan tasks.
	SubscribeProgress(ctx context.Context, handler func(context.Context, types.ScanProgress) error) error

	// PublishRule publishes the rules for the scanner to use.
	PublishRule(ctx context.Context, rule types.GitleaksRuleMessage) error
	// SubscribeRules listens for rules to be used by the scanner.
	SubscribeRules(ctx context.Context, handler func(context.Context, types.GitleaksRuleMessage) error) error
}
