package scanning

import (
	"net/netip"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// ScannerStatus represents the operational status of a scanner.
type ScannerStatus string

// Scanner status enum values.
const (
	ScannerStatusOnline      ScannerStatus = "online"
	ScannerStatusOffline     ScannerStatus = "offline"
	ScannerStatusMaintenance ScannerStatus = "maintenance"
	ScannerStatusError       ScannerStatus = "error"
	ScannerStatusUnknown     ScannerStatus = "unknown"
)

// Scanner represents a scanning agent in the system capable of executing scan jobs.
// It is an aggregate root in the scanning domain that encapsulates the identity,
// state, and behavior of an individual scanning agent along with its lifecycle.
type Scanner struct {
	id            uuid.UUID
	groupID       uuid.UUID
	name          string
	version       string
	lastHeartbeat time.Time
	status        ScannerStatus
	ipAddress     netip.Addr
	hostname      string
	metadata      map[string]any
	createdAt     time.Time
	updatedAt     time.Time
}

// NewScanner creates a new scanner with the given parameters.
func NewScanner(id, groupID uuid.UUID, name, version string) *Scanner {
	now := time.Now().UTC()
	return &Scanner{
		id:            id,
		groupID:       groupID,
		name:          name,
		version:       version,
		status:        ScannerStatusOnline,
		lastHeartbeat: now,
		createdAt:     now,
		updatedAt:     now,
		metadata:      make(map[string]any),
	}
}

// ID returns the unique identifier for this scanner.
func (s *Scanner) ID() uuid.UUID { return s.id }

// GroupID returns the identifier of the group this scanner belongs to.
func (s *Scanner) GroupID() uuid.UUID { return s.groupID }

// Name returns the human-readable name of this scanner.
func (s *Scanner) Name() string { return s.name }

// Version returns the software version of this scanner.
func (s *Scanner) Version() string { return s.version }

// LastHeartbeat returns when this scanner last sent a heartbeat.
func (s *Scanner) LastHeartbeat() time.Time { return s.lastHeartbeat }

// Status returns the current operational status of this scanner.
func (s *Scanner) Status() ScannerStatus { return s.status }

// IPAddress returns the IP address of this scanner, if known.
func (s *Scanner) IPAddress() *netip.Addr { return &s.ipAddress }

// Hostname returns the network hostname of this scanner, if known.
func (s *Scanner) Hostname() string { return s.hostname }

// Metadata returns additional metadata about this scanner.
func (s *Scanner) Metadata() map[string]any { return s.metadata }

// CreatedAt returns when this scanner was registered.
func (s *Scanner) CreatedAt() time.Time { return s.createdAt }

// UpdatedAt returns when this scanner was last updated.
func (s *Scanner) UpdatedAt() time.Time { return s.updatedAt }

// SetGroup changes the group this scanner belongs to.
func (s *Scanner) SetGroup(groupID uuid.UUID) {
	s.groupID = groupID
	s.updatedAt = time.Now().UTC()
}

// SetStatus updates the scanner's operational status.
func (s *Scanner) SetStatus(status ScannerStatus) {
	s.status = status
	s.updatedAt = time.Now().UTC()
}

// UpdateHeartbeat records a new heartbeat timestamp.
func (s *Scanner) UpdateHeartbeat() {
	s.lastHeartbeat = time.Now().UTC()
	s.updatedAt = s.lastHeartbeat
}

// SetIPAddress updates the scanner's IP address.
func (s *Scanner) SetIPAddress(ip *netip.Addr) {
	s.ipAddress = *ip
	s.updatedAt = time.Now().UTC()
}

// SetHostname updates the scanner's hostname.
func (s *Scanner) SetHostname(hostname string) {
	s.hostname = hostname
	s.updatedAt = time.Now().UTC()
}

// SetMetadata updates the scanner's metadata.
func (s *Scanner) SetMetadata(metadata map[string]any) {
	s.metadata = metadata
	s.updatedAt = time.Now().UTC()
}

// WithCreatedAt sets the creation timestamp (primarily for reconstruction from storage).
func (s *Scanner) WithCreatedAt(t time.Time) *Scanner {
	s.createdAt = t
	return s
}

// WithUpdatedAt sets the update timestamp (primarily for reconstruction from storage).
func (s *Scanner) WithUpdatedAt(t time.Time) *Scanner {
	s.updatedAt = t
	return s
}

// WithLastHeartbeat sets the heartbeat timestamp (primarily for reconstruction from storage).
func (s *Scanner) WithLastHeartbeat(t time.Time) *Scanner {
	s.lastHeartbeat = t
	return s
}
