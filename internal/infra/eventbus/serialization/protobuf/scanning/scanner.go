package scanning

import (
	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// ScannerRegisteredEventToProto converts a domain ScannerRegisteredEvent to a protobuf message.
func ScannerRegisteredEventToProto(event scanning.ScannerRegisteredEvent) *pb.ScannerRegisteredEvent {
	return &pb.ScannerRegisteredEvent{
		ScannerId:     event.ScannerID().String(),
		Name:          event.Name(),
		Version:       event.Version(),
		Capabilities:  event.Capabilities(),
		GroupName:     event.GroupName(),
		Hostname:      event.Hostname(),
		IpAddress:     event.IPAddress(),
		Timestamp:     event.OccurredAt().UnixNano(),
		Tags:          event.Tags(),
		InitialStatus: pb.ScannerStatus(event.InitialStatus().Int32()),
	}
}

// ProtoToScannerRegisteredEvent converts a protobuf message to a domain ScannerRegisteredEvent.
func ProtoToScannerRegisteredEvent(event *pb.ScannerRegisteredEvent) (scanning.ScannerRegisteredEvent, error) {
	if event == nil {
		return scanning.ScannerRegisteredEvent{}, serializationerrors.ErrNilEvent{}
	}

	scannerID, err := uuid.Parse(event.ScannerId)
	if err != nil {
		return scanning.ScannerRegisteredEvent{}, err
	}

	status := scanning.ScannerStatusFromInt32(int32(event.InitialStatus))

	regEvent := scanning.NewScannerRegisteredEvent(
		scannerID,
		event.Name,
		event.Version,
		event.Capabilities,
		event.Hostname,
		event.IpAddress,
		event.GroupName,
		event.Tags,
		status,
	)

	return regEvent, nil
}

// ScannerHeartbeatEventToProto converts a domain ScannerHeartbeatEvent to a protobuf message.
func ScannerHeartbeatEventToProto(event scanning.ScannerHeartbeatEvent) *pb.ScannerHeartbeatEvent {
	return &pb.ScannerHeartbeatEvent{
		ScannerId: event.ScannerID().String(),
		Status:    pb.ScannerStatus(event.Status().Int32()),
		Timestamp: event.OccurredAt().UnixNano(),
		Metrics:   event.Metrics(),
	}
}

// ProtoToScannerHeartbeatEvent converts a protobuf message to a domain ScannerHeartbeatEvent.
func ProtoToScannerHeartbeatEvent(event *pb.ScannerHeartbeatEvent) (scanning.ScannerHeartbeatEvent, error) {
	if event == nil {
		return scanning.ScannerHeartbeatEvent{}, serializationerrors.ErrNilEvent{}
	}

	scannerID, err := uuid.Parse(event.ScannerId)
	if err != nil {
		return scanning.ScannerHeartbeatEvent{}, err
	}

	status := scanning.ScannerStatusFromInt32(int32(event.Status))
	heartbeatEvent := scanning.NewScannerHeartbeatEvent(scannerID, status, event.Metrics)

	return heartbeatEvent, nil
}

// ScannerStatusChangedEventToProto converts a domain ScannerStatusChangedEvent to a protobuf message.
func ScannerStatusChangedEventToProto(event scanning.ScannerStatusChangedEvent) *pb.ScannerStatusChangedEvent {
	return &pb.ScannerStatusChangedEvent{
		ScannerId:      event.ScannerID().String(),
		NewStatus:      pb.ScannerStatus(event.NewStatus().Int32()),
		PreviousStatus: pb.ScannerStatus(event.PreviousStatus().Int32()),
		Reason:         event.Reason(),
		Timestamp:      event.OccurredAt().UnixNano(),
	}
}

// ProtoToScannerStatusChangedEvent converts a protobuf message to a domain ScannerStatusChangedEvent.
func ProtoToScannerStatusChangedEvent(event *pb.ScannerStatusChangedEvent) (scanning.ScannerStatusChangedEvent, error) {
	if event == nil {
		return scanning.ScannerStatusChangedEvent{}, serializationerrors.ErrNilEvent{}
	}

	scannerID, err := uuid.Parse(event.ScannerId)
	if err != nil {
		return scanning.ScannerStatusChangedEvent{}, err
	}

	newStatus := scanning.ScannerStatusFromInt32(int32(event.NewStatus))
	prevStatus := scanning.ScannerStatusFromInt32(int32(event.PreviousStatus))
	statusEvent := scanning.NewScannerStatusChangedEvent(scannerID, newStatus, prevStatus, event.Reason)

	return statusEvent, nil
}

// ScannerDeregisteredEventToProto converts a domain ScannerDeregisteredEvent to a protobuf message.
func ScannerDeregisteredEventToProto(event scanning.ScannerDeregisteredEvent) *pb.ScannerDeregisteredEvent {
	return &pb.ScannerDeregisteredEvent{
		ScannerId: event.ScannerID().String(),
		Reason:    event.Reason(),
		Timestamp: event.OccurredAt().UnixNano(),
	}
}

// ProtoToScannerDeregisteredEvent converts a protobuf message to a domain ScannerDeregisteredEvent.
func ProtoToScannerDeregisteredEvent(event *pb.ScannerDeregisteredEvent) (scanning.ScannerDeregisteredEvent, error) {
	if event == nil {
		return scanning.ScannerDeregisteredEvent{}, serializationerrors.ErrNilEvent{}
	}

	scannerID, err := uuid.Parse(event.ScannerId)
	if err != nil {
		return scanning.ScannerDeregisteredEvent{}, err
	}

	deregEvent := scanning.NewScannerDeregisteredEvent(scannerID, event.Reason)

	return deregEvent, nil
}
