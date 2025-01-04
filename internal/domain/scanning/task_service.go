package scanning

import (
	"fmt"
	"time"
)

// TaskDomainService exposes domain-level behaviors for manipulating tasks.
// It does not deal with repositories, concurrency, or caching—just rules.
type TaskDomainService interface {
	UpdateProgress(task *ScanTask, progress ScanProgress) error
	MarkTaskStale(task *ScanTask, reason StallReason) error
	RecoverTask(task *ScanTask) error
}

// TaskDomainServiceImpl is a concrete domain service that implements the business rules
// for scanning tasks, without talking to external systems or infrastructure.
type TaskDomainServiceImpl struct{}

func NewTaskDomainService() TaskDomainService {
	return &TaskDomainServiceImpl{}
}

// UpdateProgress applies domain rules to update a task with new progress.
// e.g., ignore out-of-order updates, set fields, etc.
func (ds *TaskDomainServiceImpl) UpdateProgress(task *ScanTask, progress ScanProgress) error {
	if progress.SequenceNum <= task.GetLastSequenceNum() {
		// Domain rule: ignore out-of-order
		return nil
	}
	task.UpdateProgress(progress)
	return nil
}

// MarkTaskStale sets the task status to STALE, and applies any domain-level rules
// (like storing the stall reason, last updated time).
func (ds *TaskDomainServiceImpl) MarkTaskStale(task *ScanTask, reason StallReason) error {
	if task.GetStatus() == TaskStatusCompleted {
		return fmt.Errorf("cannot mark a completed task as stale")
	}
	task.UpdateProgress(ScanProgress{
		Status:    TaskStatusStale,
		Timestamp: time.Now(),
	})
	return nil
}

// RecoverTask is a domain-level operation that modifies the task to resume scanning.
func (ds *TaskDomainServiceImpl) RecoverTask(task *ScanTask) error {
	// e.g., set status back to IN_PROGRESS if it was STALE
	if task.GetStatus() == TaskStatusStale {
		task.UpdateProgress(ScanProgress{
			Status:    TaskStatusInProgress,
			Timestamp: time.Now(),
		})
	}
	// domain logic might do more
	return nil
}
