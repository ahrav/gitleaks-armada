package scanning

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
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
func ProtoToTaskStartedEvent(pbEvent *pb.TaskStartedEvent) (scanning.TaskStartedEvent, error) {
	jobID, err := uuid.Parse(pbEvent.JobId)
	if err != nil {
		return scanning.TaskStartedEvent{}, fmt.Errorf("parse job ID: %w", err)
	}

	taskID, err := uuid.Parse(pbEvent.TaskId)
	if err != nil {
		return scanning.TaskStartedEvent{}, fmt.Errorf("parse task ID: %w", err)
	}

	return scanning.NewTaskStartedEvent(jobID, taskID, pbEvent.ResourceUri), nil
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
func ProtoToTaskProgressedEvent(pbEvent *pb.TaskProgressedEvent) (scanning.TaskProgressedEvent, error) {
	taskID, err := uuid.Parse(pbEvent.TaskId)
	if err != nil {
		return scanning.TaskProgressedEvent{}, fmt.Errorf("parse task ID: %w", err)
	}

	jobID, err := uuid.Parse(pbEvent.JobId)
	if err != nil {
		return scanning.TaskProgressedEvent{}, fmt.Errorf("parse job ID: %w", err)
	}

	var checkpoint *scanning.Checkpoint
	if pbEvent.Checkpoint != nil {
		checkpointTaskID, err := uuid.Parse(pbEvent.Checkpoint.TaskId)
		if err != nil {
			return scanning.TaskProgressedEvent{}, fmt.Errorf("parse checkpoint task ID: %w", err)
		}

		checkpoint = scanning.ReconstructCheckpoint(
			checkpointTaskID,
			time.Unix(0, pbEvent.Checkpoint.Timestamp),
			pbEvent.Checkpoint.ResumeToken,
			pbEvent.Checkpoint.Metadata,
		)
	}

	progress := scanning.ReconstructProgress(
		taskID,
		jobID,
		pbEvent.SequenceNum,
		time.Unix(0, pbEvent.Timestamp),
		pbEvent.ItemsProcessed,
		pbEvent.ErrorCount,
		pbEvent.Message,
		pbEvent.ProgressDetails,
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
	jobID, err := uuid.Parse(pbEvent.JobId)
	if err != nil {
		return scanning.TaskCompletedEvent{}, fmt.Errorf("parse job ID: %w", err)
	}

	taskID, err := uuid.Parse(pbEvent.TaskId)
	if err != nil {
		return scanning.TaskCompletedEvent{}, fmt.Errorf("parse task ID: %w", err)
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
		return scanning.TaskFailedEvent{}, fmt.Errorf("parse job ID: %w", err)
	}

	taskID, err := uuid.Parse(pbEvent.TaskId)
	if err != nil {
		return scanning.TaskFailedEvent{}, fmt.Errorf("parse task ID: %w", err)
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
	taskID, err := uuid.Parse(pbEvent.TaskId)
	if err != nil {
		return scanning.TaskHeartbeatEvent{}, fmt.Errorf("parse task ID: %w", err)
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
	if cp := event.Checkpoint; cp != nil {
		checkpoint = &pb.Checkpoint{
			TaskId:      cp.TaskID().String(),
			Timestamp:   cp.Timestamp().UnixNano(),
			ResumeToken: cp.ResumeToken(),
			Metadata:    cp.Metadata(),
		}
	}

	return &pb.TaskResumeEvent{
		JobId:       event.JobID.String(),
		TaskId:      event.TaskID.String(),
		SourceType:  taskSourceTypeToProto[event.SourceType],
		Timestamp:   event.OccurredAt().UnixNano(),
		ResourceUri: event.ResourceURI,
		SequenceNum: int64(event.SequenceNum),
		Checkpoint:  checkpoint,
	}
}

var protoSourceTypeToTaskSourceType = map[pb.SourceType]shared.SourceType{
	pb.SourceType_SOURCE_TYPE_GITHUB: shared.SourceTypeGitHub,
	pb.SourceType_SOURCE_TYPE_S3:     shared.SourceTypeS3,
	pb.SourceType_SOURCE_TYPE_URL:    shared.SourceTypeURL,
}

// ProtoToTaskResumeEvent converts a protobuf TaskResumeEvent to its domain representation.
func ProtoToTaskResumeEvent(pbEvent *pb.TaskResumeEvent) (scanning.TaskResumeEvent, error) {
	jobID, err := uuid.Parse(pbEvent.JobId)
	if err != nil {
		return scanning.TaskResumeEvent{}, fmt.Errorf("parse job ID: %w", err)
	}

	taskID, err := uuid.Parse(pbEvent.TaskId)
	if err != nil {
		return scanning.TaskResumeEvent{}, fmt.Errorf("parse task ID: %w", err)
	}

	var checkpoint *scanning.Checkpoint
	if pbEvent.Checkpoint != nil {
		checkpointTaskID, err := uuid.Parse(pbEvent.Checkpoint.TaskId)
		if err != nil {
			return scanning.TaskResumeEvent{}, fmt.Errorf("parse checkpoint task ID: %w", err)
		}

		checkpoint = scanning.ReconstructCheckpoint(
			checkpointTaskID,
			time.Unix(0, pbEvent.Checkpoint.Timestamp),
			pbEvent.Checkpoint.ResumeToken,
			pbEvent.Checkpoint.Metadata,
		)
	}

	return scanning.NewTaskResumeEvent(
		jobID,
		taskID,
		protoSourceTypeToTaskSourceType[pbEvent.SourceType],
		pbEvent.ResourceUri,
		int(pbEvent.SequenceNum),
		checkpoint,
	), nil
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
	jobID, err := uuid.Parse(p.JobId)
	if err != nil {
		return scanning.TaskJobMetricEvent{}, fmt.Errorf("parse job ID: %w", err)
	}

	taskID, err := uuid.Parse(p.TaskId)
	if err != nil {
		return scanning.TaskJobMetricEvent{}, fmt.Errorf("parse task ID: %w", err)
	}

	return scanning.NewTaskJobMetricEvent(
		jobID,
		taskID,
		ProtoToTaskStatus(p.Status),
	), nil
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
