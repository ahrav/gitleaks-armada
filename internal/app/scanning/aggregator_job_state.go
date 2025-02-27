package scanning

import (
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// AggregatorJobState tracks the state and progress of a scanning job.
// It maintains counts of tasks in various states and determines when a job
// should transition to different states based on its constituent tasks.
type AggregatorJobState struct {
	jobID           uuid.UUID
	enumerationDone bool // Indicates if all tasks for this job have been enumerated
	finalTaskCount  int  // Total number of tasks in this job after enumeration completes

	// Task status counters.
	completedCount int
	failedCount    int
	pausedCount    int
	cancelledCount int

	// Job state flags.
	jobFinalized bool
	jobPaused    bool
	jobCancelled bool
}

// updateTaskCounts updates the internal task counters based on status transitions.
// It handles both status changes for existing tasks and new task additions,
// ensuring the job's state accurately reflects its constituent tasks.
func (s *AggregatorJobState) updateTaskCounts(oldStatus, newStatus domain.TaskStatus) {
	// Handle completion status changes.
	if newStatus == domain.TaskStatusCompleted && oldStatus != domain.TaskStatusCompleted {
		s.completedCount++
	}
	if newStatus == domain.TaskStatusFailed && oldStatus != domain.TaskStatusFailed {
		s.failedCount++
	}
	if newStatus == domain.TaskStatusPaused && oldStatus != domain.TaskStatusPaused {
		s.pausedCount++
	}
	if oldStatus == domain.TaskStatusPaused && newStatus != domain.TaskStatusPaused {
		s.pausedCount--
		s.jobPaused = false // Reset jobPaused when a task transitions out of PAUSED state
	}
	if newStatus == domain.TaskStatusCancelled && oldStatus != domain.TaskStatusCancelled {
		s.cancelledCount++
	}

	// Handle status transitions away from retryable terminal states.
	// If a previously terminal task transitions away from failed, decrement
	// the relevant counter.
	// TODO: This will need to get updated once we support retrying tasks.
	if oldStatus == domain.TaskStatusFailed && newStatus != domain.TaskStatusFailed {
		s.failedCount--
	}
}

// shouldPauseJob determines if the job should transition to a paused state.
// Returns true when all non-terminal tasks are paused, which indicates the
// entire job should be considered paused.
func (s *AggregatorJobState) shouldPauseJob() bool {
	// We should pause the job if:
	// 1. We have at least one task (finalTaskCount > 0)
	// 2. All non-terminal tasks are paused (pausedCount == activeTaskCount)
	// 3. Job hasn't been paused yet
	if s.finalTaskCount == 0 || s.jobPaused {
		return false
	}

	activeTaskCount := s.finalTaskCount - (s.completedCount + s.failedCount)
	return activeTaskCount > 0 && s.pausedCount == activeTaskCount
}

// shouldCancelJob determines if the job should transition to a cancelled state.
// Returns true when all non-terminal tasks are cancelled, which indicates the
// entire job should be considered cancelled.
func (s *AggregatorJobState) shouldCancelJob() bool {
	// We should cancel the job if:
	// 1. We have at least one task (finalTaskCount > 0)
	// 2. All non-terminal tasks are cancelled (cancelledCount == activeTaskCount)
	// 3. Job hasn't been cancelled yet
	if s.finalTaskCount == 0 || s.jobCancelled {
		return false
	}

	activeTaskCount := s.finalTaskCount - (s.completedCount + s.failedCount)
	return activeTaskCount > 0 && s.cancelledCount == activeTaskCount
}

// setEnumerationComplete marks the job's enumeration phase as complete and sets the final task count.
// This is called once all tasks for the job have been identified and created.
func (s *AggregatorJobState) setEnumerationComplete(taskCount int) {
	s.enumerationDone = true
	s.finalTaskCount = taskCount
}

// isDone determines if the job has completed all its work.
// Returns true if task enumeration is finished and all tasks have reached a terminal state
// (either completed or failed).
func (s *AggregatorJobState) isDone() bool {
	return s.enumerationDone &&
		s.finalTaskCount > 0 &&
		(s.completedCount+s.failedCount) == s.finalTaskCount
}
