package protobuf

import (
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// ScanProgressToProto converts domain.ScanProgress -> pb.ScanProgress.
func ScanProgressToProto(sp events.ScanProgress) *pb.ScanProgress {
	return &pb.ScanProgress{
		TaskId:          sp.TaskID,
		PercentComplete: sp.PercentComplete,
		ItemsProcessed:  sp.ItemsProcessed,
		TotalItems:      sp.TotalItems,
		Metadata:        sp.Metadata,
		// current_item is optional. If you want to store it in domain,
		// you could keep it in sp.Metadata["current_item"] or make a new field in domain.
	}
}

// ProtoToScanProgress converts pb.ScanProgress -> domain.ScanProgress.
func ProtoToScanProgress(psp *pb.ScanProgress) events.ScanProgress {
	return events.ScanProgress{
		TaskID:          psp.TaskId,
		PercentComplete: psp.PercentComplete,
		ItemsProcessed:  psp.ItemsProcessed,
		TotalItems:      psp.TotalItems,
		Metadata:        psp.Metadata,
	}
}
