package scanning

// JobMetrics tracks quantitative measures for a scan job.
type JobMetrics struct {
	totalTasks     int
	completedTasks int
	failedTasks    int
}

// NewJobMetrics creates a new JobMetrics instance.
func NewJobMetrics() *JobMetrics { return new(JobMetrics) }

// TotalTasks returns the total number of tasks.
func (m *JobMetrics) TotalTasks() int { return m.totalTasks }

// CompletedTasks returns the number of completed tasks.
func (m *JobMetrics) CompletedTasks() int { return m.completedTasks }

// FailedTasks returns the number of failed tasks.
func (m *JobMetrics) FailedTasks() int { return m.failedTasks }

// SetTotalTasks updates the total number of tasks.
func (m *JobMetrics) SetTotalTasks(total int) { m.totalTasks = total }

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
