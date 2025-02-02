package scanning

import (
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// TaskStartedEventToProto converts a domain TaskStartedEvent to its protobuf representation.
func TaskStartedEventToProto(event scanning.TaskStartedEvent) *pb.TaskStartedEvent {
	return &pb.TaskStartedEvent{
		JobId:       event.JobID.String(),
		TaskId:      event.TaskID.String(),
		Timestamp:   event.OccurredAt().UnixNano(),
		ResourceUri: event.ResourceURI,
	}
}

// ProtoToTaskStartedEvent converts a protobuf TaskStartedEvent to its domain representation.
func ProtoToTaskStartedEvent(event *pb.TaskStartedEvent) (*scanning.TaskStartedEvent, error) {
	if event == nil {
		return nil, serializationerrors.ErrNilEvent{EventType: "TaskStarted"}
	}

	jobID, err := uuid.Parse(event.JobId)
	if err != nil {
		return nil, serializationerrors.ErrInvalidUUID{Field: "job ID", Err: err}
	}

	taskID, err := uuid.Parse(event.TaskId)
	if err != nil {
		return nil, serializationerrors.ErrInvalidUUID{Field: "task ID", Err: err}
	}

	return &scanning.TaskStartedEvent{
		JobID:       jobID,
		TaskID:      taskID,
		ResourceURI: event.ResourceUri,
	}, nil
}

// TaskProgressedEventToProto converts a domain TaskProgressedEvent to its protobuf representation.
func TaskProgressedEventToProto(event scanning.TaskProgressedEvent) *pb.TaskProgressedEvent {
	progress := event.Progress

	var checkpoint *pb.Checkpoint
	if cp := progress.Checkpoint(); cp != nil {
		checkpoint = &pb.Checkpoint{
			TaskId:      cp.TaskID().String(),
			Timestamp:   cp.Timestamp().UnixNano(),
			ResumeToken: cp.ResumeToken(),
			Metadata:    cp.Metadata(),
		}
	}

	return &pb.TaskProgressedEvent{
		TaskId:          progress.TaskID().String(),
		JobId:           progress.JobID().String(),
		SequenceNum:     progress.SequenceNum(),
		Timestamp:       progress.Timestamp().UnixNano(),
		ItemsProcessed:  progress.ItemsProcessed(),
		ErrorCount:      progress.ErrorCount(),
		Message:         progress.Message(),
		ProgressDetails: progress.ProgressDetails(),
		Checkpoint:      checkpoint,
	}
}

// ProtoToTaskProgressedEvent converts a protobuf TaskProgressedEvent to its domain representation.
func ProtoToTaskProgressedEvent(event *pb.TaskProgressedEvent) (scanning.TaskProgressedEvent, error) {
	if event == nil {
		return scanning.TaskProgressedEvent{}, serializationerrors.ErrNilEvent{EventType: "TaskProgressed"}
	}

	taskID, err := uuid.Parse(event.TaskId)
	if err != nil {
		return scanning.TaskProgressedEvent{}, serializationerrors.ErrInvalidUUID{Field: "task ID", Err: err}
	}

	jobID, err := uuid.Parse(event.JobId)
	if err != nil {
		return scanning.TaskProgressedEvent{}, serializationerrors.ErrInvalidUUID{Field: "job ID", Err: err}
	}

	var checkpoint *scanning.Checkpoint
	if event.Checkpoint != nil {
		checkpointTaskID, err := uuid.Parse(event.Checkpoint.TaskId)
		if err != nil {
			return scanning.TaskProgressedEvent{}, serializationerrors.ErrInvalidUUID{Field: "checkpoint task ID", Err: err}
		}

		checkpoint = scanning.ReconstructCheckpoint(
			checkpointTaskID,
			time.Unix(0, event.Checkpoint.Timestamp),
			event.Checkpoint.ResumeToken,
			event.Checkpoint.Metadata,
		)
	}

	progress := scanning.ReconstructProgress(
		taskID,
		jobID,
		event.SequenceNum,
		time.Unix(0, event.Timestamp),
		event.ItemsProcessed,
		event.ErrorCount,
		event.Message,
		event.ProgressDetails,
		checkpoint,
	)

	return scanning.NewTaskProgressedEvent(progress), nil
}

// TaskCompletedEventToProto converts a domain TaskCompletedEvent to its protobuf representation.
func TaskCompletedEventToProto(event scanning.TaskCompletedEvent) *pb.TaskCompletedEvent {
	return &pb.TaskCompletedEvent{
		JobId:     event.JobID.String(),
		TaskId:    event.TaskID.String(),
		Timestamp: event.OccurredAt().UnixNano(),
	}
}

// ProtoToTaskCompletedEvent converts a protobuf TaskCompletedEvent to its domain representation.
func ProtoToTaskCompletedEvent(pbEvent *pb.TaskCompletedEvent) (scanning.TaskCompletedEvent, error) {
	if pbEvent == nil {
		return scanning.TaskCompletedEvent{}, serializationerrors.ErrNilEvent{EventType: "TaskCompleted"}
	}

	jobID, err := uuid.Parse(pbEvent.JobId)
	if err != nil {
		return scanning.TaskCompletedEvent{}, serializationerrors.ErrInvalidUUID{Field: "job ID", Err: err}
	}

	taskID, err := uuid.Parse(pbEvent.TaskId)
	if err != nil {
		return scanning.TaskCompletedEvent{}, serializationerrors.ErrInvalidUUID{Field: "task ID", Err: err}
	}

	return scanning.NewTaskCompletedEvent(jobID, taskID), nil
}

// TaskFailedEventToProto converts a domain TaskFailedEvent to its protobuf representation.
func TaskFailedEventToProto(event scanning.TaskFailedEvent) *pb.TaskFailedEvent {
	return &pb.TaskFailedEvent{
		JobId:     event.JobID.String(),
		TaskId:    event.TaskID.String(),
		Timestamp: event.OccurredAt().UnixNano(),
		Reason:    event.Reason,
	}
}

// ProtoToTaskFailedEvent converts a protobuf TaskFailedEvent to its domain representation.
func ProtoToTaskFailedEvent(pbEvent *pb.TaskFailedEvent) (scanning.TaskFailedEvent, error) {
	jobID, err := uuid.Parse(pbEvent.JobId)
	if err != nil {
		return scanning.TaskFailedEvent{}, serializationerrors.ErrInvalidUUID{Field: "job ID", Err: err}
	}

	taskID, err := uuid.Parse(pbEvent.TaskId)
	if err != nil {
		return scanning.TaskFailedEvent{}, serializationerrors.ErrInvalidUUID{Field: "task ID", Err: err}
	}

	return scanning.NewTaskFailedEvent(jobID, taskID, pbEvent.Reason), nil
}

// TaskHeartbeatEventToProto converts a domain TaskHeartbeatEvent to its protobuf representation.
func TaskHeartbeatEventToProto(event scanning.TaskHeartbeatEvent) *pb.TaskHeartbeatEvent {
	return &pb.TaskHeartbeatEvent{
		TaskId:    event.TaskID.String(),
		Timestamp: event.OccurredAt().UnixNano(),
	}
}

// ProtoToTaskHeartbeatEvent converts a protobuf TaskHeartbeatEvent to its domain representation.
func ProtoToTaskHeartbeatEvent(pbEvent *pb.TaskHeartbeatEvent) (scanning.TaskHeartbeatEvent, error) {
	if pbEvent == nil {
		return scanning.TaskHeartbeatEvent{}, serializationerrors.ErrNilEvent{EventType: "TaskHeartbeat"}
	}

	taskID, err := uuid.Parse(pbEvent.TaskId)
	if err != nil {
		return scanning.TaskHeartbeatEvent{}, serializationerrors.ErrInvalidUUID{Field: "task ID", Err: err}
	}

	return scanning.NewTaskHeartbeatEvent(taskID), nil
}

var taskSourceTypeToProto = map[shared.SourceType]pb.SourceType{
	shared.SourceTypeGitHub: pb.SourceType_SOURCE_TYPE_GITHUB,
	shared.SourceTypeS3:     pb.SourceType_SOURCE_TYPE_S3,
	shared.SourceTypeURL:    pb.SourceType_SOURCE_TYPE_URL,
}

// TaskResumeEventToProto converts a domain TaskResumeEvent to its protobuf representation.
func TaskResumeEventToProto(event scanning.TaskResumeEvent) *pb.TaskResumeEvent {
	var checkpoint *pb.Checkpoint
	if event.Checkpoint != nil {
		checkpoint = &pb.Checkpoint{
			TaskId:      event.Checkpoint.TaskID().String(),
			Timestamp:   event.Checkpoint.Timestamp().UnixNano(),
			ResumeToken: event.Checkpoint.ResumeToken(),
			Metadata:    event.Checkpoint.Metadata(),
		}
	}

	return &pb.TaskResumeEvent{
		JobId:       event.JobID.String(),
		TaskId:      event.TaskID.String(),
		SourceType:  taskSourceTypeToProto[event.SourceType],
		ResourceUri: event.ResourceURI,
		SequenceNum: int64(event.SequenceNum),
		Timestamp:   time.Now().UnixNano(),
		Checkpoint:  checkpoint,
	}
}

var protoSourceTypeToTaskSourceType = map[pb.SourceType]shared.SourceType{
	pb.SourceType_SOURCE_TYPE_GITHUB: shared.SourceTypeGitHub,
	pb.SourceType_SOURCE_TYPE_S3:     shared.SourceTypeS3,
	pb.SourceType_SOURCE_TYPE_URL:    shared.SourceTypeURL,
}

// ProtoToTaskResumeEvent converts a protobuf TaskResumeEvent to its domain representation.
func ProtoToTaskResumeEvent(event *pb.TaskResumeEvent) (*scanning.TaskResumeEvent, error) {
	if event == nil {
		return nil, serializationerrors.ErrNilEvent{EventType: "TaskResume"}
	}

	jobID, err := uuid.Parse(event.JobId)
	if err != nil {
		return nil, serializationerrors.ErrInvalidUUID{Field: "job ID", Err: err}
	}

	taskID, err := uuid.Parse(event.TaskId)
	if err != nil {
		return nil, serializationerrors.ErrInvalidUUID{Field: "task ID", Err: err}
	}

	var checkpoint *scanning.Checkpoint
	if event.Checkpoint != nil {
		checkpointTaskID, err := uuid.Parse(event.Checkpoint.TaskId)
		if err != nil {
			return nil, serializationerrors.ErrInvalidUUID{Field: "checkpoint task ID", Err: err}
		}

		checkpoint = scanning.ReconstructCheckpoint(
			checkpointTaskID,
			time.Unix(0, event.Checkpoint.Timestamp),
			event.Checkpoint.ResumeToken,
			event.Checkpoint.Metadata,
		)
	}

	sourceType, exists := protoSourceTypeToTaskSourceType[event.SourceType]
	if !exists {
		return nil, serializationerrors.ErrInvalidSourceType{Value: event.SourceType}
	}

	result := scanning.NewTaskResumeEvent(
		jobID,
		taskID,
		sourceType,
		event.ResourceUri,
		int(event.SequenceNum),
		checkpoint,
	)
	return &result, nil
}

// TaskJobMetricEventToProto converts a domain TaskJobMetricEvent to protobuf.
func TaskJobMetricEventToProto(e scanning.TaskJobMetricEvent) *pb.TaskJobMetricEvent {
	return &pb.TaskJobMetricEvent{
		JobId:     e.JobID.String(),
		TaskId:    e.TaskID.String(),
		Status:    TaskStatusToProto(e.Status),
		Timestamp: e.OccurredAt().UnixNano(),
	}
}

// ProtoToTaskJobMetricEvent converts a protobuf TaskJobMetricEvent to domain event.
func ProtoToTaskJobMetricEvent(p *pb.TaskJobMetricEvent) (scanning.TaskJobMetricEvent, error) {
	if p == nil {
		return scanning.TaskJobMetricEvent{}, serializationerrors.ErrNilEvent{EventType: "TaskJobMetric"}
	}

	jobID, err := uuid.Parse(p.JobId)
	if err != nil {
		return scanning.TaskJobMetricEvent{}, serializationerrors.ErrInvalidUUID{Field: "job ID", Err: err}
	}

	taskID, err := uuid.Parse(p.TaskId)
	if err != nil {
		return scanning.TaskJobMetricEvent{}, serializationerrors.ErrInvalidUUID{Field: "task ID", Err: err}
	}

	status := ProtoToTaskStatus(p.Status)
	return scanning.NewTaskJobMetricEvent(jobID, taskID, status), nil
}

// TaskStatusToProto converts a domain TaskStatus to its protobuf representation.
func TaskStatusToProto(s scanning.TaskStatus) pb.TaskStatus {
	switch s {
	case scanning.TaskStatusPending:
		return pb.TaskStatus_TASK_STATUS_PENDING
	case scanning.TaskStatusInProgress:
		return pb.TaskStatus_TASK_STATUS_IN_PROGRESS
	case scanning.TaskStatusCompleted:
		return pb.TaskStatus_TASK_STATUS_COMPLETED
	case scanning.TaskStatusFailed:
		return pb.TaskStatus_TASK_STATUS_FAILED
	default:
		return pb.TaskStatus_TASK_STATUS_UNSPECIFIED
	}
}

// ProtoToTaskStatus converts a protobuf TaskStatus to its domain representation.
func ProtoToTaskStatus(s pb.TaskStatus) scanning.TaskStatus {
	switch s {
	case pb.TaskStatus_TASK_STATUS_PENDING:
		return scanning.TaskStatusPending
	case pb.TaskStatus_TASK_STATUS_IN_PROGRESS:
		return scanning.TaskStatusInProgress
	case pb.TaskStatus_TASK_STATUS_COMPLETED:
		return scanning.TaskStatusCompleted
	case pb.TaskStatus_TASK_STATUS_FAILED:
		return scanning.TaskStatusFailed
	default:
		return scanning.TaskStatusUnspecified
	}
}
