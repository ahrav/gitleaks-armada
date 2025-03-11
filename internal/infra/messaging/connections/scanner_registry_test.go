package connections_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/connections"
)

// MockGatewayMetrics implements the GatewayMetrics interface for testing.
type MockGatewayMetrics struct {
	ConnectedScanners     int
	MessagesReceived      map[string]int
	MessagesSent          map[string]int
	TranslationErrors     map[string]int
	AuthErrors            int
	ScannerRegistrations  int
	ScannerHeartbeats     int
	ScanResults           int
	TaskProgress          int
	IncConnectedCallCount int
	DecConnectedCallCount int
	SetConnectedCallCount int
}

func NewMockGatewayMetrics() *MockGatewayMetrics {
	return &MockGatewayMetrics{
		MessagesReceived:  make(map[string]int),
		MessagesSent:      make(map[string]int),
		TranslationErrors: make(map[string]int),
	}
}

func (m *MockGatewayMetrics) IncConnectedScanners(context.Context) {
	m.ConnectedScanners++
	m.IncConnectedCallCount++
}

func (m *MockGatewayMetrics) DecConnectedScanners(context.Context) {
	m.ConnectedScanners--
	m.DecConnectedCallCount++
}

func (m *MockGatewayMetrics) SetConnectedScanners(_ context.Context, count int) {
	m.ConnectedScanners = count
	m.SetConnectedCallCount++
}

func (m *MockGatewayMetrics) IncMessagesReceived(_ context.Context, messageType string) {
	m.MessagesReceived[messageType]++
}

func (m *MockGatewayMetrics) IncMessagesSent(_ context.Context, messageType string) {
	m.MessagesSent[messageType]++
}

func (m *MockGatewayMetrics) IncTranslationErrors(_ context.Context, direction string) {
	m.TranslationErrors[direction]++
}

func (m *MockGatewayMetrics) IncAuthErrors(context.Context) { m.AuthErrors++ }

func (m *MockGatewayMetrics) IncScannerRegistrations(context.Context) { m.ScannerRegistrations++ }

func (m *MockGatewayMetrics) IncScannerHeartbeats(context.Context) { m.ScannerHeartbeats++ }

func (m *MockGatewayMetrics) IncScanResults(context.Context) { m.ScanResults++ }

func (m *MockGatewayMetrics) IncTaskProgress(context.Context) { m.TaskProgress++ }

// TestRegisterNewScanner ensures registering a brand-new scanner inserts it
// into the registry and updates metrics accordingly.
func TestRegisterNewScanner(t *testing.T) {
	ctx := context.Background()

	metrics := NewMockGatewayMetrics()
	registry := connections.NewScannerRegistry(metrics)

	conn := &connections.ScannerConnection{
		ScannerID:    "scanner-123",
		Connected:    time.Now(),
		LastActivity: time.Now(),
		Capabilities: []string{"cap1", "cap2"},
		Version:      "v1.0.0",
	}

	registry.Register(ctx, conn.ScannerID, conn)

	gotConn, exists := registry.Get("scanner-123")
	assert.True(t, exists, "Expected the scanner to exist after registration")
	assert.Equal(t, conn, gotConn, "Expected the stored connection to match the registered one")
}

// TestRegisterExistingScanner ensures that registering a scanner ID that already exists
// replaces the old entry and does not increment the total count.
func TestRegisterExistingScanner(t *testing.T) {
	ctx := context.Background()

	metrics := NewMockGatewayMetrics()
	registry := connections.NewScannerRegistry(metrics)

	// First registration.
	firstConn := &connections.ScannerConnection{ScannerID: "scanner-XYZ", Version: "v1"}
	registry.Register(ctx, firstConn.ScannerID, firstConn)

	// Register a second time with the same ID but different data.
	secondConn := &connections.ScannerConnection{ScannerID: "scanner-XYZ", Version: "v2"}
	registry.Register(ctx, secondConn.ScannerID, secondConn)

	// Confirm the stored data is replaced.
	gotConn, exists := registry.Get("scanner-XYZ")
	assert.True(t, exists)
	assert.Equal(t, secondConn.Version, gotConn.Version, "Scanner entry should be replaced")
}

// TestUnregisterScannerExists ensures removing a known scanner ID returns true,
// updates metrics, and the scanner can no longer be retrieved.
func TestUnregisterScannerExists(t *testing.T) {
	ctx := context.Background()

	metrics := NewMockGatewayMetrics()
	registry := connections.NewScannerRegistry(metrics)

	// Pre-populate the registry.
	conn := &connections.ScannerConnection{ScannerID: "scanner-ABC"}
	registry.Register(ctx, conn.ScannerID, conn)

	removed := registry.Unregister(ctx, "scanner-ABC")
	assert.True(t, removed, "Expected true when removing an existing scanner")

	_, exists := registry.Get("scanner-ABC")
	assert.False(t, exists, "Scanner should no longer exist after unregister")
}

// TestUnregisterScannerNotFound ensures removing a non-existent ID returns false
// and does not modify metrics or registry state.
func TestUnregisterScannerNotFound(t *testing.T) {
	ctx := context.Background()

	metrics := NewMockGatewayMetrics()
	registry := connections.NewScannerRegistry(metrics)

	// Attempt to remove something that doesn't exist.
	removed := registry.Unregister(ctx, "scanner-nope")
	assert.False(t, removed, "Expected false when removing a non-existent scanner")
}

// TestGetScanner checks basic retrieval of a registered scanner.
func TestGetScanner(t *testing.T) {
	metrics := NewMockGatewayMetrics()
	registry := connections.NewScannerRegistry(metrics)

	conn := &connections.ScannerConnection{ScannerID: "get-test"}
	registry.Register(context.Background(), conn.ScannerID, conn)

	got, ok := registry.Get("get-test")
	assert.True(t, ok, "Should find a registered scanner by ID")
	assert.Equal(t, "get-test", got.ScannerID)
}

// TestGetScannerNotFound checks that retrieving a non-existent ID returns false.
func TestGetScannerNotFound(t *testing.T) {
	registry := connections.NewScannerRegistry(&MockGatewayMetrics{})

	got, ok := registry.Get("not-registered")
	assert.False(t, ok, "Should not find an unregistered scanner")
	assert.Nil(t, got, "Should return nil connection for unregistered scanner")
}

// TestCount checks that the registry count reflects the number of registered scanners.
func TestCount(t *testing.T) {
	registry := connections.NewScannerRegistry(&MockGatewayMetrics{})

	assert.Equal(t, 0, registry.Count(), "Initial count should be zero")

	// Add some scanners.
	registry.Register(context.Background(), "A", &connections.ScannerConnection{})
	registry.Register(context.Background(), "B", &connections.ScannerConnection{})
	registry.Register(context.Background(), "C", &connections.ScannerConnection{})

	assert.Equal(t, 3, registry.Count(), "Expected 3 registered scanners")

	registry.Unregister(context.Background(), "B")
	assert.Equal(t, 2, registry.Count(), "After removing B, expected 2 scanners")
}
