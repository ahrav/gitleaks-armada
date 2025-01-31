package scanning

// JobMetrics tracks quantitative measures for a scan job.
type JobMetrics struct {
	totalTasks      int
	inProgressTasks int
	completedTasks  int
	failedTasks     int
	staleTasks      int
}

// NewJobMetrics creates a new JobMetrics instance.
func NewJobMetrics() *JobMetrics { return new(JobMetrics) }

// ReconstructJobMetrics creates a JobMetrics instance from stored fields.
func ReconstructJobMetrics(totalTasks, completedTasks, failedTasks, staleTasks int) *JobMetrics {
	return &JobMetrics{
		totalTasks:     totalTasks,
		completedTasks: completedTasks,
		failedTasks:    failedTasks,
		staleTasks:     staleTasks,
	}
}

// Clone returns a deep copy of the JobMetrics.
func (m *JobMetrics) Clone() *JobMetrics {
	return &JobMetrics{
		totalTasks:      m.totalTasks,
		inProgressTasks: m.inProgressTasks,
		completedTasks:  m.completedTasks,
		failedTasks:     m.failedTasks,
		staleTasks:      m.staleTasks,
	}
}

// TotalTasks returns the total number of tasks.
func (m *JobMetrics) TotalTasks() int { return m.totalTasks }

// CompletedTasks returns the number of completed tasks.
func (m *JobMetrics) CompletedTasks() int { return m.completedTasks }

// FailedTasks returns the number of failed tasks.
func (m *JobMetrics) FailedTasks() int { return m.failedTasks }

// StaleTasks returns the number of stale tasks.
func (m *JobMetrics) StaleTasks() int { return m.staleTasks }

// SetTotalTasks updates the total number of tasks.
func (m *JobMetrics) SetTotalTasks(total int) { m.totalTasks = total }

// InProgressTasks returns the number of in progress tasks.
func (m *JobMetrics) InProgressTasks() int { return m.inProgressTasks }

// OnTaskAdded updates metrics for a newly created task with the given status.
func (m *JobMetrics) OnTaskAdded(status TaskStatus) {
	m.totalTasks++
	switch status {
	case TaskStatusPending:
		// Do nothing.
	case TaskStatusInProgress:
		m.inProgressTasks++
	case TaskStatusStale:
		m.staleTasks++
	case TaskStatusCompleted:
		m.completedTasks++
	case TaskStatusFailed:
		m.failedTasks++
	}
}

// OnTaskRemoved updates metrics if a task was removed entirely from the job.
func (m *JobMetrics) OnTaskRemoved(status TaskStatus) {
	m.totalTasks--
	switch status {
	case TaskStatusInProgress, TaskStatusStale:
		m.inProgressTasks--
	case TaskStatusCompleted:
		m.completedTasks--
	case TaskStatusFailed:
		m.failedTasks--
	}
}

// OnTaskStatusChanged updates metrics after a task changes from oldStatus to newStatus.
func (m *JobMetrics) OnTaskStatusChanged(oldStatus, newStatus TaskStatus) {
	// Decrement old
	switch oldStatus {
	case TaskStatusInProgress:
		m.inProgressTasks--
	case TaskStatusCompleted:
		m.completedTasks--
	case TaskStatusFailed:
		m.failedTasks--
	case TaskStatusStale:
		m.staleTasks--
	}
	// Increment new
	switch newStatus {
	case TaskStatusInProgress:
		m.inProgressTasks++
	case TaskStatusCompleted:
		m.completedTasks++
	case TaskStatusFailed:
		m.failedTasks++
	case TaskStatusStale:
		m.staleTasks++
	}
}

// UpdateTaskCounts updates the completed and failed task counts.
func (m *JobMetrics) UpdateTaskCounts(completed, failed int) {
	m.completedTasks = completed
	m.failedTasks = failed
}

// CompletionPercentage calculates the percentage of completed tasks.
func (m *JobMetrics) CompletionPercentage() float64 {
	if m.totalTasks == 0 {
		return 0
	}
	return float64(m.completedTasks) / float64(m.totalTasks) * 100
}
