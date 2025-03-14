package scanning

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

func TestTaskStartedEventConversion(t *testing.T) {
	t.Run("successful conversions", func(t *testing.T) {
		jobID := uuid.New()
		taskID := uuid.New()
		scannerID := uuid.New()
		resourceURI := "test://resource"
		domainEvent := scanning.NewTaskStartedEvent(jobID, taskID, scannerID, resourceURI)

		// Test domain to proto conversion.
		protoEvent := TaskStartedEventToProto(domainEvent)
		require.NotNil(t, protoEvent)
		assert.Equal(t, jobID.String(), protoEvent.JobId)
		assert.Equal(t, taskID.String(), protoEvent.TaskId)
		assert.Equal(t, scannerID.String(), protoEvent.ScannerId)
		assert.Equal(t, resourceURI, protoEvent.ResourceUri)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToTaskStartedEvent(protoEvent)
		require.NoError(t, err)
		require.NotNil(t, convertedEvent)
		assert.Equal(t, jobID, convertedEvent.JobID)
		assert.Equal(t, taskID, convertedEvent.TaskID)
		assert.Equal(t, scannerID, convertedEvent.ScannerID)
		assert.Equal(t, resourceURI, convertedEvent.ResourceURI)
	})

	t.Run("error cases", func(t *testing.T) {
		testCases := []struct {
			name    string
			event   *pb.TaskStartedEvent
			wantErr error
		}{
			{
				name:    "nil event",
				event:   nil,
				wantErr: serializationerrors.ErrNilEvent{EventType: "TaskStarted"},
			},
			{
				name: "invalid job ID",
				event: &pb.TaskStartedEvent{
					JobId:  "invalid",
					TaskId: uuid.New().String(),
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "job ID"},
			},
			{
				name: "invalid task ID",
				event: &pb.TaskStartedEvent{
					JobId:  uuid.New().String(),
					TaskId: "invalid",
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "task ID"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ProtoToTaskStartedEvent(tc.event)
				assert.IsType(t, tc.wantErr, err)
			})
		}
	})
}

func TestTaskProgressedEventConversion(t *testing.T) {
	t.Run("successful conversion with checkpoint", func(t *testing.T) {
		jobID := uuid.New()
		taskID := uuid.New()
		timestamp := time.Now()
		checkpoint := scanning.ReconstructCheckpoint(
			taskID,
			timestamp,
			[]byte("resume-token"),
			map[string]string{"key": "value"},
		)

		progress := scanning.ReconstructProgress(
			taskID,
			jobID,
			1,
			timestamp,
			100,
			2,
			"progress message",
			json.RawMessage(`{"detail": "value"}`),
			checkpoint,
		)

		// Test domain to proto conversion.
		domainEvent := scanning.NewTaskProgressedEvent(progress)
		protoEvent := TaskProgressedEventToProto(domainEvent)

		assert.Equal(t, jobID.String(), protoEvent.JobId)
		assert.Equal(t, taskID.String(), protoEvent.TaskId)
		assert.Equal(t, int64(100), protoEvent.ItemsProcessed)
		require.NotNil(t, protoEvent.Checkpoint)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToTaskProgressedEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, jobID, convertedEvent.Progress.JobID())
		assert.Equal(t, taskID, convertedEvent.Progress.TaskID())
	})

	t.Run("error cases", func(t *testing.T) {
		testCases := []struct {
			name    string
			event   *pb.TaskProgressedEvent
			wantErr error
		}{
			{
				name:    "nil event",
				event:   nil,
				wantErr: serializationerrors.ErrNilEvent{EventType: "TaskProgressed"},
			},
			{
				name: "invalid task ID",
				event: &pb.TaskProgressedEvent{
					JobId:  uuid.New().String(),
					TaskId: "invalid",
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "task ID"},
			},
			{
				name: "invalid checkpoint task ID",
				event: &pb.TaskProgressedEvent{
					JobId:  uuid.New().String(),
					TaskId: uuid.New().String(),
					Checkpoint: &pb.Checkpoint{
						TaskId: "invalid",
					},
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "checkpoint task ID"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ProtoToTaskProgressedEvent(tc.event)
				assert.IsType(t, tc.wantErr, err)
			})
		}
	})
}

func TestTaskStatusConversion(t *testing.T) {
	t.Run("valid status conversions", func(t *testing.T) {
		testCases := []struct {
			name         string
			domainStatus scanning.TaskStatus
			protoStatus  pb.TaskStatus
		}{
			{"Pending", scanning.TaskStatusPending, pb.TaskStatus_TASK_STATUS_PENDING},
			{"InProgress", scanning.TaskStatusInProgress, pb.TaskStatus_TASK_STATUS_IN_PROGRESS},
			{"Completed", scanning.TaskStatusCompleted, pb.TaskStatus_TASK_STATUS_COMPLETED},
			{"Failed", scanning.TaskStatusFailed, pb.TaskStatus_TASK_STATUS_FAILED},
			{"Unspecified", scanning.TaskStatusUnspecified, pb.TaskStatus_TASK_STATUS_UNSPECIFIED},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				protoStatus := taskStatusToProto(tc.domainStatus)
				assert.Equal(t, tc.protoStatus, protoStatus)

				domainStatus := protoToTaskStatus(tc.protoStatus)
				assert.Equal(t, tc.domainStatus, domainStatus)
			})
		}
	})

	t.Run("invalid status handling", func(t *testing.T) {
		// Test invalid domain status converts to UNSPECIFIED proto status.
		invalidDomainStatus := scanning.TaskStatus("INVALID_STATUS")
		protoStatus := taskStatusToProto(invalidDomainStatus)
		assert.Equal(t, pb.TaskStatus_TASK_STATUS_UNSPECIFIED, protoStatus)

		// Test invalid proto status converts to TaskStatusUnspecified.
		invalidProtoStatus := pb.TaskStatus(-1)
		domainStatus := protoToTaskStatus(invalidProtoStatus)
		assert.Equal(t, scanning.TaskStatusUnspecified, domainStatus)
	})
}

func TestTaskResumeEventConversion(t *testing.T) {
	t.Run("successful conversions", func(t *testing.T) {
		jobID := uuid.New()
		taskID := uuid.New()
		resourceURI := "test://resource"
		sequenceNum := 5
		auth := scanning.NewAuth(string(scanning.AuthTypeNone), map[string]any{"username": "testuser", "password": "testpass"})

		domainEvent := scanning.NewTaskResumeEvent(
			jobID,
			taskID,
			shared.SourceTypeGitHub,
			resourceURI,
			sequenceNum,
			nil,
			auth,
		)

		// Test domain to proto conversion.
		protoEvent, err := TaskResumeEventToProto(domainEvent)
		require.NoError(t, err)
		assert.Equal(t, jobID.String(), protoEvent.JobId)
		assert.Equal(t, taskID.String(), protoEvent.TaskId)
		assert.Equal(t, pb.SourceType_SOURCE_TYPE_GITHUB, protoEvent.SourceType)
		assert.Equal(t, resourceURI, protoEvent.ResourceUri)
		assert.Equal(t, int64(sequenceNum), protoEvent.SequenceNum)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToTaskResumeEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, jobID, convertedEvent.JobID)
		assert.Equal(t, taskID, convertedEvent.TaskID)
		assert.Equal(t, shared.SourceTypeGitHub, convertedEvent.SourceType)
	})

	t.Run("error cases", func(t *testing.T) {
		testCases := []struct {
			name    string
			event   *pb.TaskResumeEvent
			wantErr error
		}{
			{
				name:    "nil event",
				event:   nil,
				wantErr: serializationerrors.ErrNilEvent{EventType: "TaskResume"},
			},
			{
				name: "invalid job ID",
				event: &pb.TaskResumeEvent{
					JobId:  "invalid",
					TaskId: uuid.New().String(),
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "job ID"},
			},
			{
				name: "invalid task ID",
				event: &pb.TaskResumeEvent{
					JobId:  uuid.New().String(),
					TaskId: "invalid",
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "task ID"},
			},
			{
				name: "invalid source type",
				event: &pb.TaskResumeEvent{
					JobId:      uuid.New().String(),
					TaskId:     uuid.New().String(),
					SourceType: pb.SourceType(-1),
				},
				wantErr: serializationerrors.ErrInvalidSourceType{Value: pb.SourceType(-1)},
			},
			{
				name: "invalid checkpoint task ID",
				event: &pb.TaskResumeEvent{
					JobId:  uuid.New().String(),
					TaskId: uuid.New().String(),
					Checkpoint: &pb.Checkpoint{
						TaskId: "invalid",
					},
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "checkpoint task ID"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ProtoToTaskResumeEvent(tc.event)
				assert.IsType(t, tc.wantErr, err)
			})
		}
	})
}

func TestTaskJobMetricEventConversion(t *testing.T) {
	t.Run("successful conversions", func(t *testing.T) {
		jobID := uuid.New()
		taskID := uuid.New()
		domainEvent := scanning.NewTaskJobMetricEvent(jobID, taskID, scanning.TaskStatusCompleted)

		// Test domain to proto conversion.
		protoEvent := TaskJobMetricEventToProto(domainEvent)
		assert.Equal(t, jobID.String(), protoEvent.JobId)
		assert.Equal(t, taskID.String(), protoEvent.TaskId)
		assert.Equal(t, pb.TaskStatus_TASK_STATUS_COMPLETED, protoEvent.Status)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToTaskJobMetricEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, jobID, convertedEvent.JobID)
		assert.Equal(t, taskID, convertedEvent.TaskID)
		assert.Equal(t, scanning.TaskStatusCompleted, convertedEvent.Status)
	})

	t.Run("error cases", func(t *testing.T) {
		testCases := []struct {
			name    string
			event   *pb.TaskJobMetricEvent
			wantErr error
		}{
			{
				name:    "nil event",
				event:   nil,
				wantErr: serializationerrors.ErrNilEvent{EventType: "TaskJobMetric"},
			},
			{
				name: "invalid job ID",
				event: &pb.TaskJobMetricEvent{
					JobId:  "invalid",
					TaskId: uuid.New().String(),
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "job ID"},
			},
			{
				name: "invalid task ID",
				event: &pb.TaskJobMetricEvent{
					JobId:  uuid.New().String(),
					TaskId: "invalid",
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "task ID"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ProtoToTaskJobMetricEvent(tc.event)
				assert.IsType(t, tc.wantErr, err)
			})
		}
	})
}

func TestTaskPausedEventConversion(t *testing.T) {
	t.Run("successful conversions", func(t *testing.T) {
		jobID := uuid.New()
		taskID := uuid.New()
		requestedBy := "test-user"
		progress := scanning.NewProgress(
			taskID,
			jobID,
			1,
			time.Now(),
			100,
			0,
			"test progress",
			nil,
			nil,
		)

		domainEvent := scanning.NewTaskPausedEvent(jobID, taskID, progress, requestedBy)

		// Test domain to proto conversion.
		protoEvent := TaskPausedEventToProto(domainEvent)
		require.NotNil(t, protoEvent)
		assert.Equal(t, jobID.String(), protoEvent.JobId)
		assert.Equal(t, taskID.String(), protoEvent.TaskId)
		assert.Equal(t, requestedBy, protoEvent.RequestedBy)
		require.NotNil(t, protoEvent.Progress)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToTaskPausedEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, jobID, convertedEvent.JobID)
		assert.Equal(t, taskID, convertedEvent.TaskID)
		assert.Equal(t, requestedBy, convertedEvent.RequestedBy)
		require.NotNil(t, convertedEvent.Progress)
		assert.Equal(t, progress.ItemsProcessed(), convertedEvent.Progress.ItemsProcessed())
	})

	t.Run("error cases", func(t *testing.T) {
		testCases := []struct {
			name    string
			event   *pb.TaskPausedEvent
			wantErr error
		}{
			{
				name:    "nil event",
				event:   nil,
				wantErr: serializationerrors.ErrNilEvent{EventType: "TaskPaused"},
			},
			{
				name: "invalid job ID",
				event: &pb.TaskPausedEvent{
					JobId:  "invalid",
					TaskId: uuid.New().String(),
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "job ID"},
			},
			{
				name: "invalid task ID",
				event: &pb.TaskPausedEvent{
					JobId:  uuid.New().String(),
					TaskId: "invalid",
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "task ID"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ProtoToTaskPausedEvent(tc.event)
				assert.IsType(t, tc.wantErr, err)
			})
		}
	})
}

func TestTaskCancelledEventConversion(t *testing.T) {
	t.Parallel()

	jobID := uuid.New()
	taskID := uuid.New()
	requestedBy := "test-user"

	domainEvent := scanning.NewTaskCancelledEvent(jobID, taskID, requestedBy)

	protoEvent := TaskCancelledEventToProto(domainEvent)

	// Verify proto conversion.
	assert.Equal(t, jobID.String(), protoEvent.JobId)
	assert.Equal(t, taskID.String(), protoEvent.TaskId)
	assert.Equal(t, requestedBy, protoEvent.RequestedBy)
	assert.NotZero(t, protoEvent.Timestamp)
	assert.NotZero(t, protoEvent.CancelledAt)

	reconvertedEvent, err := ProtoToTaskCancelledEvent(protoEvent)
	require.NoError(t, err)

	// Verify domain conversion.
	assert.Equal(t, jobID, reconvertedEvent.JobID)
	assert.Equal(t, taskID, reconvertedEvent.TaskID)
	assert.Equal(t, requestedBy, reconvertedEvent.RequestedBy)

	t.Run("nil event", func(t *testing.T) {
		_, err := ProtoToTaskCancelledEvent(nil)
		assert.Error(t, err)
	})

	t.Run("invalid job ID", func(t *testing.T) {
		invalidProto := &pb.TaskCancelledEvent{
			JobId:  "invalid-uuid",
			TaskId: taskID.String(),
		}
		_, err := ProtoToTaskCancelledEvent(invalidProto)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "job ID")
	})

	t.Run("invalid task ID", func(t *testing.T) {
		invalidProto := &pb.TaskCancelledEvent{
			JobId:  jobID.String(),
			TaskId: "invalid-uuid",
		}
		_, err := ProtoToTaskCancelledEvent(invalidProto)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "task ID")
	})
}
