package protobuf

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// TaskStartedEventToProto converts a domain TaskStartedEvent to its protobuf representation
func TaskStartedEventToProto(event scanning.TaskStartedEvent) *pb.TaskStartedEvent {
	return &pb.TaskStartedEvent{
		JobId:     event.JobID.String(),
		TaskId:    event.TaskID.String(),
		Timestamp: event.OccurredAt().UnixNano(),
	}
}

// ProtoToTaskStartedEvent converts a protobuf TaskStartedEvent to its domain representation
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
