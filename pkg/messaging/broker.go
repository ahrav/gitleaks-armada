package messaging

import "context"

// Broker handles task distribution and result collection via message queue.
type Broker interface {
	// PublishTask publishes a task for workers to process.
	PublishTask(ctx context.Context, task Task) error
	// PublishTasks publishes multiple tasks in a batch.
	PublishTasks(ctx context.Context, tasks []Task) error
	// SubscribeTasks listens for new tasks to be processed by workers.
	SubscribeTasks(ctx context.Context, handler func(context.Context, Task) error) error

	// PublishResult publishes the findings and status from a completed scan task.
	PublishResult(ctx context.Context, result ScanResult) error
	// SubscribeResults listens for completed scan results to be collected by orchestrator.
	SubscribeResults(ctx context.Context, handler func(context.Context, ScanResult) error) error

	// PublishProgress publishes progress updates for a scan task.
	PublishProgress(ctx context.Context, progress ScanProgress) error
	// SubscribeProgress listens for progress updates from ongoing scan tasks.
	SubscribeProgress(ctx context.Context, handler func(context.Context, ScanProgress) error) error

	// PublishRules publishes the rules for the scanner to use.
	PublishRules(ctx context.Context, ruleSet GitleaksRuleSet) error
	// SubscribeRules listens for rules to be used by the scanner.
	SubscribeRules(ctx context.Context, handler func(context.Context, GitleaksRuleSet) error) error
}
