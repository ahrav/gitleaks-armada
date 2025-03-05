package scanning

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

func TestScannerRegisteredEventConversion(t *testing.T) {
	t.Run("successful conversion", func(t *testing.T) {
		scannerID := uuid.New()
		name := "test-scanner"
		version := "1.0.0"
		capabilities := []string{"git", "s3"}
		groupName := "test-group"
		hostname := "test-host"
		ipAddress := "192.168.1.1"
		tags := map[string]string{"env": "test", "region": "us-west-2"}
		initialStatus := scanning.ScannerStatusOnline

		domainEvent := scanning.NewScannerRegisteredEvent(
			scannerID,
			name,
			version,
			capabilities,
			hostname,
			ipAddress,
			groupName,
			tags,
			initialStatus,
		)

		// Test domain to proto conversion.
		protoEvent := ScannerRegisteredEventToProto(domainEvent)
		require.NotNil(t, protoEvent)
		assert.Equal(t, scannerID.String(), protoEvent.ScannerId)
		assert.Equal(t, name, protoEvent.Name)
		assert.Equal(t, version, protoEvent.Version)
		assert.Equal(t, capabilities, protoEvent.Capabilities)
		assert.Equal(t, groupName, protoEvent.GroupName)
		assert.Equal(t, hostname, protoEvent.Hostname)
		assert.Equal(t, ipAddress, protoEvent.IpAddress)
		assert.Equal(t, tags, protoEvent.Tags)
		assert.Equal(t, pb.ScannerStatus(initialStatus.Int32()), protoEvent.InitialStatus)
		assert.Equal(t, domainEvent.OccurredAt().UnixNano(), protoEvent.Timestamp)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToScannerRegisteredEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, scannerID, convertedEvent.ScannerID())
		assert.Equal(t, name, convertedEvent.Name())
		assert.Equal(t, version, convertedEvent.Version())
		assert.Equal(t, capabilities, convertedEvent.Capabilities())
		assert.Equal(t, groupName, convertedEvent.GroupName())
		assert.Equal(t, hostname, convertedEvent.Hostname())
		assert.Equal(t, ipAddress, convertedEvent.IPAddress())
		assert.Equal(t, tags, convertedEvent.Tags())
		assert.Equal(t, initialStatus, convertedEvent.InitialStatus())
	})

	t.Run("invalid UUID", func(t *testing.T) {
		protoEvent := &pb.ScannerRegisteredEvent{
			ScannerId:     "invalid-uuid",
			Name:          "test-scanner",
			Version:       "1.0.0",
			Capabilities:  []string{"git"},
			GroupName:     "test-group",
			Hostname:      "test-host",
			IpAddress:     "192.168.1.1",
			Timestamp:     0,
			Tags:          map[string]string{},
			InitialStatus: pb.ScannerStatus_SCANNER_STATUS_ONLINE,
		}

		_, err := ProtoToScannerRegisteredEvent(protoEvent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid UUID")
	})

	t.Run("nil event", func(t *testing.T) {
		_, err := ProtoToScannerRegisteredEvent(nil)
		require.Error(t, err)
		assert.IsType(t, serializationerrors.ErrNilEvent{}, err)
	})
}

func TestScannerHeartbeatEventConversion(t *testing.T) {
	t.Run("successful conversion", func(t *testing.T) {
		scannerID := uuid.New()
		status := scanning.ScannerStatusBusy
		metrics := map[string]float64{
			"cpu_usage":    0.75,
			"memory_usage": 0.5,
		}

		domainEvent := scanning.NewScannerHeartbeatEvent(scannerID, status, metrics)

		// Test domain to proto conversion.
		protoEvent := ScannerHeartbeatEventToProto(domainEvent)
		require.NotNil(t, protoEvent)
		assert.Equal(t, scannerID.String(), protoEvent.ScannerId)
		assert.Equal(t, pb.ScannerStatus(status.Int32()), protoEvent.Status)
		assert.Equal(t, metrics, protoEvent.Metrics)
		assert.Equal(t, domainEvent.OccurredAt().UnixNano(), protoEvent.Timestamp)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToScannerHeartbeatEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, scannerID, convertedEvent.ScannerID())
		assert.Equal(t, status, convertedEvent.Status())
		assert.Equal(t, metrics, convertedEvent.Metrics())
	})

	t.Run("invalid UUID", func(t *testing.T) {
		protoEvent := &pb.ScannerHeartbeatEvent{
			ScannerId: "invalid-uuid",
			Status:    pb.ScannerStatus_SCANNER_STATUS_BUSY,
			Timestamp: 0,
			Metrics:   map[string]float64{},
		}

		_, err := ProtoToScannerHeartbeatEvent(protoEvent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid UUID")
	})

	t.Run("nil event", func(t *testing.T) {
		_, err := ProtoToScannerHeartbeatEvent(nil)
		require.Error(t, err)
		assert.IsType(t, serializationerrors.ErrNilEvent{}, err)
	})
}

func TestScannerStatusChangedEventConversion(t *testing.T) {
	t.Run("successful conversion", func(t *testing.T) {
		scannerID := uuid.New()
		newStatus := scanning.ScannerStatusBusy
		previousStatus := scanning.ScannerStatusOnline
		reason := "scanner started processing tasks"

		domainEvent := scanning.NewScannerStatusChangedEvent(scannerID, newStatus, previousStatus, reason)

		// Test domain to proto conversion.
		protoEvent := ScannerStatusChangedEventToProto(domainEvent)
		require.NotNil(t, protoEvent)
		assert.Equal(t, scannerID.String(), protoEvent.ScannerId)
		assert.Equal(t, pb.ScannerStatus(newStatus.Int32()), protoEvent.NewStatus)
		assert.Equal(t, pb.ScannerStatus(previousStatus.Int32()), protoEvent.PreviousStatus)
		assert.Equal(t, reason, protoEvent.Reason)
		assert.Equal(t, domainEvent.OccurredAt().UnixNano(), protoEvent.Timestamp)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToScannerStatusChangedEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, scannerID, convertedEvent.ScannerID())
		assert.Equal(t, newStatus, convertedEvent.NewStatus())
		assert.Equal(t, previousStatus, convertedEvent.PreviousStatus())
		assert.Equal(t, reason, convertedEvent.Reason())
	})

	t.Run("invalid UUID", func(t *testing.T) {
		protoEvent := &pb.ScannerStatusChangedEvent{
			ScannerId:      "invalid-uuid",
			NewStatus:      pb.ScannerStatus_SCANNER_STATUS_BUSY,
			PreviousStatus: pb.ScannerStatus_SCANNER_STATUS_ONLINE,
			Reason:         "test reason",
			Timestamp:      0,
		}

		_, err := ProtoToScannerStatusChangedEvent(protoEvent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid UUID")
	})

	t.Run("nil event", func(t *testing.T) {
		_, err := ProtoToScannerStatusChangedEvent(nil)
		require.Error(t, err)
		assert.IsType(t, serializationerrors.ErrNilEvent{}, err)
	})
}

func TestScannerDeregisteredEventConversion(t *testing.T) {
	t.Run("successful conversion", func(t *testing.T) {
		scannerID := uuid.New()
		reason := "scanner shutdown gracefully"

		domainEvent := scanning.NewScannerDeregisteredEvent(scannerID, reason)

		// Test domain to proto conversion.
		protoEvent := ScannerDeregisteredEventToProto(domainEvent)
		require.NotNil(t, protoEvent)
		assert.Equal(t, scannerID.String(), protoEvent.ScannerId)
		assert.Equal(t, reason, protoEvent.Reason)
		assert.Equal(t, domainEvent.OccurredAt().UnixNano(), protoEvent.Timestamp)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToScannerDeregisteredEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, scannerID, convertedEvent.ScannerID())
		assert.Equal(t, reason, convertedEvent.Reason())
	})

	t.Run("invalid UUID", func(t *testing.T) {
		protoEvent := &pb.ScannerDeregisteredEvent{
			ScannerId: "invalid-uuid",
			Reason:    "test reason",
			Timestamp: 0,
		}

		_, err := ProtoToScannerDeregisteredEvent(protoEvent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid UUID")
	})

	t.Run("nil event", func(t *testing.T) {
		_, err := ProtoToScannerDeregisteredEvent(nil)
		require.Error(t, err)
		assert.IsType(t, serializationerrors.ErrNilEvent{}, err)
	})
}
