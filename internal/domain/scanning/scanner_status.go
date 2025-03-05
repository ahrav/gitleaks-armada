package scanning

import (
	"fmt"

	pb "github.com/ahrav/gitleaks-armada/proto"
)

// ScannerStatus represents the possible states of a scanner in the system.
type ScannerStatus string

// Define scanner status constants
const (
	ScannerStatusUnspecified ScannerStatus = "UNSPECIFIED"
	ScannerStatusOnline      ScannerStatus = "ONLINE"
	ScannerStatusOffline     ScannerStatus = "OFFLINE"
	ScannerStatusMaintenance ScannerStatus = "MAINTENANCE"
	ScannerStatusError       ScannerStatus = "ERROR"
)

// String returns the string representation of the ScannerStatus.
func (s ScannerStatus) String() string {
	return string(s)
}

// Int32 returns the protobuf enum int32 value for this status.
func (s ScannerStatus) Int32() int32 {
	switch s {
	case ScannerStatusUnspecified:
		return int32(pb.ScannerStatus_SCANNER_STATUS_UNSPECIFIED)
	case ScannerStatusOnline:
		return int32(pb.ScannerStatus_SCANNER_STATUS_ONLINE)
	case ScannerStatusOffline:
		return int32(pb.ScannerStatus_SCANNER_STATUS_OFFLINE)
	case ScannerStatusMaintenance:
		return int32(pb.ScannerStatus_SCANNER_STATUS_MAINTENANCE)
	case ScannerStatusError:
		return int32(pb.ScannerStatus_SCANNER_STATUS_ERROR)
	default:
		return int32(pb.ScannerStatus_SCANNER_STATUS_UNSPECIFIED)
	}
}

// ProtoEnum returns the protobuf enum value for this status.
func (s ScannerStatus) ProtoEnum() pb.ScannerStatus {
	return pb.ScannerStatus(s.Int32())
}

// ProtoString returns the protobuf enum string for this status.
func (s ScannerStatus) ProtoString() string {
	switch s {
	case ScannerStatusUnspecified:
		return "SCANNER_STATUS_UNSPECIFIED"
	case ScannerStatusOnline:
		return "SCANNER_STATUS_ONLINE"
	case ScannerStatusOffline:
		return "SCANNER_STATUS_OFFLINE"
	case ScannerStatusMaintenance:
		return "SCANNER_STATUS_MAINTENANCE"
	case ScannerStatusError:
		return "SCANNER_STATUS_ERROR"
	default:
		return "SCANNER_STATUS_UNSPECIFIED"
	}
}

// ScannerStatusFromInt32 converts a protobuf enum int32 value to a ScannerStatus.
func ScannerStatusFromInt32(i int32) ScannerStatus {
	switch i {
	case int32(pb.ScannerStatus_SCANNER_STATUS_UNSPECIFIED):
		return ScannerStatusUnspecified
	case int32(pb.ScannerStatus_SCANNER_STATUS_ONLINE):
		return ScannerStatusOnline
	case int32(pb.ScannerStatus_SCANNER_STATUS_OFFLINE):
		return ScannerStatusOffline
	case int32(pb.ScannerStatus_SCANNER_STATUS_MAINTENANCE):
		return ScannerStatusMaintenance
	case int32(pb.ScannerStatus_SCANNER_STATUS_ERROR):
		return ScannerStatusError
	default:
		return ScannerStatusUnspecified
	}
}

// ScannerStatusFromProtoEnum converts a protobuf ScannerStatus enum to a domain ScannerStatus.
func ScannerStatusFromProtoEnum(status pb.ScannerStatus) ScannerStatus {
	return ScannerStatusFromInt32(int32(status))
}

// ParseScannerStatus converts a string to a ScannerStatus.
func ParseScannerStatus(s string) ScannerStatus {
	switch s {
	case "UNSPECIFIED", "scanner_status_unspecified", "SCANNER_STATUS_UNSPECIFIED":
		return ScannerStatusUnspecified
	case "ONLINE", "scanner_status_online", "SCANNER_STATUS_ONLINE":
		return ScannerStatusOnline
	case "OFFLINE", "scanner_status_offline", "SCANNER_STATUS_OFFLINE":
		return ScannerStatusOffline
	case "MAINTENANCE", "scanner_status_maintenance", "SCANNER_STATUS_MAINTENANCE":
		return ScannerStatusMaintenance
	case "ERROR", "scanner_status_error", "SCANNER_STATUS_ERROR":
		return ScannerStatusError
	default:
		return ScannerStatusUnspecified
	}
}

// ValidateTransition validates whether a transition from this status to the target status is valid.
func (s ScannerStatus) ValidateTransition(target ScannerStatus) error {
	if !s.IsValidTransition(target) {
		return fmt.Errorf("invalid scanner status transition from %s to %s", s, target)
	}
	return nil
}

// IsValidTransition checks if a transition from this status to the target status is valid.
func (s ScannerStatus) IsValidTransition(target ScannerStatus) bool {
	// Self transitions are always valid (staying in the same status)
	if s == target {
		return true
	}

	switch s {
	case ScannerStatusUnspecified:
		// Unspecified can transition to any specific status
		return target != ScannerStatusUnspecified
	case ScannerStatusOnline:
		// Online can transition to any other specific status
		return target != ScannerStatusUnspecified
	case ScannerStatusOffline:
		// Offline can transition to Online, Maintenance, or Error
		return target == ScannerStatusOnline ||
			target == ScannerStatusMaintenance ||
			target == ScannerStatusError
	case ScannerStatusMaintenance:
		// Maintenance can transition to Online, Offline, or Error
		return target == ScannerStatusOnline ||
			target == ScannerStatusOffline ||
			target == ScannerStatusError
	case ScannerStatusError:
		// Error can transition to any specific status except Busy
		// (must go through Online first)
		return target != ScannerStatusUnspecified
	default:
		return false
	}
}
