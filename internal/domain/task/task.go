// Package task provides shared domain entities and types for representing scan tasks
// across different packages and layers of the application. This package should be
// imported by other packages that need to work with the core task domain model.
package task

// Task represents a single scan task entity that needs to be processed.
// It contains all the information needed to locate and authenticate against
// a resource that needs to be scanned for sensitive data.
type Task struct {
	TaskID      string            // Unique identifier for the task
	ResourceURI string            // Location of the resource to scan
	Metadata    map[string]string // Additional context for task processing
	Credentials *TaskCredentials  // Authentication credentials for the resource
}

// TaskBatch is a collection of tasks to be scanned in a single batch.
type TaskBatch struct {
	Tasks []Task
}
