package scanning

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

func TestScanTask_UpdateProgress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		task     *Task
		progress Progress
		want     *Task
	}{
		{
			name: "basic update",
			task: func() *Task {
				taskID := uuid.New()
				return &Task{
					CoreTask: shared.CoreTask{
						TaskID: taskID,
					},
					lastSequenceNum: 0,
					itemsProcessed:  0,
				}
			}(),
			progress: func() Progress {
				taskID := uuid.New() // Will be overwritten in test
				return Progress{
					TaskID:         taskID,
					SequenceNum:    1,
					Status:         TaskStatusInProgress,
					ItemsProcessed: 100,
					Timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				}
			}(),
			want: func() *Task {
				taskID := uuid.New() // Will be overwritten in test
				return &Task{
					CoreTask: shared.CoreTask{
						TaskID: taskID,
					},
					lastSequenceNum: 1,
					status:          TaskStatusInProgress,
					itemsProcessed:  100,
					lastUpdate:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				}
			}(),
		},
		{
			name: "update with checkpoint",
			task: func() *Task {
				taskID := uuid.New()
				return &Task{
					CoreTask: shared.CoreTask{
						TaskID: taskID,
					},
					lastSequenceNum: 0,
				}
			}(),
			progress: func() Progress {
				taskID := uuid.New() // Will be overwritten in test
				return Progress{
					TaskID:      taskID,
					SequenceNum: 1,
					Checkpoint: &Checkpoint{
						TaskID:      taskID,
						ResumeToken: []byte("token"),
					},
				}
			}(),
			want: func() *Task {
				taskID := uuid.New() // Will be overwritten in test
				return &Task{
					CoreTask: shared.CoreTask{
						TaskID: taskID,
					},
					lastSequenceNum: 1,
					lastCheckpoint: &Checkpoint{
						TaskID:      taskID,
						ResumeToken: []byte("token"),
					},
				}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Sync the IDs across task, progress, and want.
			tt.progress.TaskID = tt.task.TaskID
			tt.want.TaskID = tt.task.TaskID

			if tt.progress.Checkpoint != nil {
				tt.progress.Checkpoint.TaskID = tt.task.TaskID
				tt.want.lastCheckpoint.TaskID = tt.task.TaskID
			}

			tt.task.UpdateProgress(tt.progress)
			assert.Equal(t, tt.want.lastSequenceNum, tt.task.lastSequenceNum)
			assert.Equal(t, tt.want.status, tt.task.status)
			assert.Equal(t, tt.want.itemsProcessed, tt.task.itemsProcessed)
			assert.Equal(t, tt.want.lastCheckpoint, tt.task.lastCheckpoint)
		})
	}
}

func TestReconstructProgress(t *testing.T) {
	taskID := uuid.New()
	now := time.Now().UTC()
	details := json.RawMessage(`{"key": "value"}`)
	checkpoint := &Checkpoint{
		TaskID:      taskID,
		Timestamp:   now,
		ResumeToken: []byte("token"),
		Metadata:    map[string]string{"meta": "data"},
	}

	tests := []struct {
		name  string
		input struct {
			taskID         uuid.UUID
			sequenceNum    int64
			timestamp      time.Time
			status         TaskStatus
			itemsProcessed int64
			errorCount     int32
			message        string
			details        json.RawMessage
			checkpoint     *Checkpoint
		}
		want Progress
	}{
		{
			name: "successful reconstruction with all fields",
			input: struct {
				taskID         uuid.UUID
				sequenceNum    int64
				timestamp      time.Time
				status         TaskStatus
				itemsProcessed int64
				errorCount     int32
				message        string
				details        json.RawMessage
				checkpoint     *Checkpoint
			}{
				taskID:         taskID,
				sequenceNum:    1,
				timestamp:      now,
				status:         TaskStatusInProgress,
				itemsProcessed: 100,
				errorCount:     2,
				message:        "test message",
				details:        details,
				checkpoint:     checkpoint,
			},
			want: Progress{
				TaskID:          taskID,
				SequenceNum:     1,
				Timestamp:       now,
				Status:          TaskStatusInProgress,
				ItemsProcessed:  100,
				ErrorCount:      2,
				Message:         "test message",
				ProgressDetails: details,
				Checkpoint:      checkpoint,
			},
		},
		{
			name: "reconstruction with minimal fields",
			input: struct {
				taskID         uuid.UUID
				sequenceNum    int64
				timestamp      time.Time
				status         TaskStatus
				itemsProcessed int64
				errorCount     int32
				message        string
				details        json.RawMessage
				checkpoint     *Checkpoint
			}{
				taskID:    taskID,
				timestamp: now,
				status:    TaskStatusInitialized,
			},
			want: Progress{
				TaskID:    taskID,
				Timestamp: now,
				Status:    TaskStatusInitialized,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReconstructProgress(
				tt.input.taskID,
				tt.input.sequenceNum,
				tt.input.timestamp,
				tt.input.status,
				tt.input.itemsProcessed,
				tt.input.errorCount,
				tt.input.message,
				tt.input.details,
				tt.input.checkpoint,
			)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReconstructCheckpoint(t *testing.T) {
	taskID := uuid.New()
	now := time.Now().UTC()
	resumeToken := []byte("token")
	metadata := map[string]string{"key": "value"}

	tests := []struct {
		name  string
		input struct {
			taskID      uuid.UUID
			timestamp   time.Time
			resumeToken []byte
			metadata    map[string]string
		}
		want *Checkpoint
	}{
		{
			name: "successful reconstruction with all fields",
			input: struct {
				taskID      uuid.UUID
				timestamp   time.Time
				resumeToken []byte
				metadata    map[string]string
			}{
				taskID:      taskID,
				timestamp:   now,
				resumeToken: resumeToken,
				metadata:    metadata,
			},
			want: &Checkpoint{
				TaskID:      taskID,
				Timestamp:   now,
				ResumeToken: resumeToken,
				Metadata:    metadata,
			},
		},
		{
			name: "reconstruction with minimal fields",
			input: struct {
				taskID      uuid.UUID
				timestamp   time.Time
				resumeToken []byte
				metadata    map[string]string
			}{
				taskID:    taskID,
				timestamp: now,
			},
			want: &Checkpoint{
				TaskID:    taskID,
				Timestamp: now,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReconstructCheckpoint(
				tt.input.taskID,
				tt.input.timestamp,
				tt.input.resumeToken,
				tt.input.metadata,
			)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewCheckpoint(t *testing.T) {
	taskID := uuid.New()
	resumeToken := []byte("token")
	metadata := map[string]string{"key": "value"}

	tests := []struct {
		name  string
		input struct {
			taskID      uuid.UUID
			resumeToken []byte
			metadata    map[string]string
		}
		validateFn func(*testing.T, *Checkpoint)
	}{
		{
			name: "successful creation with all fields",
			input: struct {
				taskID      uuid.UUID
				resumeToken []byte
				metadata    map[string]string
			}{
				taskID:      taskID,
				resumeToken: resumeToken,
				metadata:    metadata,
			},
			validateFn: func(t *testing.T, got *Checkpoint) {
				assert.Equal(t, taskID, got.TaskID)
				assert.Equal(t, resumeToken, got.ResumeToken)
				assert.Equal(t, metadata, got.Metadata)
				assert.WithinDuration(t, time.Now(), got.Timestamp, 2*time.Second)
			},
		},
		{
			name: "creation with minimal fields",
			input: struct {
				taskID      uuid.UUID
				resumeToken []byte
				metadata    map[string]string
			}{
				taskID: taskID,
			},
			validateFn: func(t *testing.T, got *Checkpoint) {
				assert.Equal(t, taskID, got.TaskID)
				assert.Nil(t, got.ResumeToken)
				assert.Nil(t, got.Metadata)
				assert.WithinDuration(t, time.Now(), got.Timestamp, 2*time.Second)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewCheckpoint(
				tt.input.taskID,
				tt.input.resumeToken,
				tt.input.metadata,
			)

			tt.validateFn(t, got)
		})
	}
}
