package scanning

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// TaskStartedEventToProto converts a domain TaskStartedEvent to its protobuf representation.
func TaskStartedEventToProto(event scanning.TaskStartedEvent) *pb.TaskStartedEvent {
	return &pb.TaskStartedEvent{
		JobId:     event.JobID.String(),
		TaskId:    event.TaskID.String(),
		Timestamp: event.OccurredAt().UnixNano(),
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

	return scanning.NewTaskStartedEvent(jobID, taskID), nil
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
		SequenceNum:     progress.SequenceNum(),
		Timestamp:       progress.Timestamp().UnixNano(),
		Status:          string(progress.Status()),
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
		pbEvent.SequenceNum,
		time.Unix(0, pbEvent.Timestamp),
		scanning.TaskStatus(pbEvent.Status),
		pbEvent.ItemsProcessed,
		pbEvent.ErrorCount,
		pbEvent.Message,
		pbEvent.ProgressDetails,
		checkpoint,
	)

	return scanning.NewTaskProgressedEvent(progress), nil
}
