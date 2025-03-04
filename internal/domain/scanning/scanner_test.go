package scanning

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

func TestNewScanner(t *testing.T) {
	tests := []struct {
		name          string
		scannerName   string
		version       string
		expectedError error
	}{
		{
			name:          "valid_scanner",
			scannerName:   "Test Scanner",
			version:       "1.0.0",
			expectedError: nil,
		},
		{
			name:          "name_too_short",
			scannerName:   "",
			version:       "1.0.0",
			expectedError: ErrNameTooShort,
		},
		{
			name:          "name_too_long",
			scannerName:   strings.Repeat("a", maxNameLength+1),
			version:       "1.0.0",
			expectedError: ErrNameTooLong,
		},
		{
			name:          "name_invalid_chars",
			scannerName:   "Test$Scanner*",
			version:       "1.0.0",
			expectedError: ErrNameInvalidChars,
		},
		{
			name:          "version_too_long",
			scannerName:   "Valid Scanner",
			version:       strings.Repeat("1", maxVersionLength+1),
			expectedError: ErrVersionTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(uuid.New(), uuid.New(), tt.scannerName, tt.version)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, scanner)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, scanner)
			assert.Equal(t, tt.scannerName, scanner.Name())
			assert.Equal(t, tt.version, scanner.Version())
			assert.NotEqual(t, uuid.UUID{}, scanner.ID())
			assert.NotEqual(t, uuid.UUID{}, scanner.GroupID())

			// Status should be online by default.
			assert.Equal(t, ScannerStatusOnline, scanner.Status())
			assert.NotNil(t, scanner.Metadata())

			assert.False(t, scanner.CreatedAt().IsZero())
			assert.False(t, scanner.UpdatedAt().IsZero())
			assert.False(t, scanner.LastHeartbeat().IsZero())

			// Created, updated, and heartbeat timestamps should be close to now
			now := time.Now().UTC()
			assert.WithinDuration(t, now, scanner.CreatedAt(), 1*time.Second)
			assert.WithinDuration(t, now, scanner.UpdatedAt(), 1*time.Second)
			assert.WithinDuration(t, now, scanner.LastHeartbeat(), 1*time.Second)
		})
	}
}

func TestScanner_SetIPAddress(t *testing.T) {
	scannerID := uuid.New()
	groupID := uuid.New()
	scanner, err := NewScanner(scannerID, groupID, "Test Scanner", "1.0.0")
	require.NoError(t, err)

	originalUpdatedAt := scanner.UpdatedAt()
	time.Sleep(10 * time.Millisecond) // Ensure time difference in UpdatedAt

	validIP, err := netip.ParseAddr("192.168.1.1")
	require.NoError(t, err)

	tests := []struct {
		name          string
		ip            *netip.Addr
		expectedError error
	}{
		{
			name:          "valid_ip",
			ip:            &validIP,
			expectedError: nil,
		},
		{
			name:          "nil_ip",
			ip:            nil,
			expectedError: ErrInvalidIPAddress,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := scanner.SetIPAddress(tt.ip)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, *tt.ip, *scanner.IPAddress())
			assert.True(t, scanner.UpdatedAt().After(originalUpdatedAt))
		})
	}
}

func TestScanner_SetHostname(t *testing.T) {
	scannerID := uuid.New()
	groupID := uuid.New()
	scanner, err := NewScanner(scannerID, groupID, "Test Scanner", "1.0.0")
	require.NoError(t, err)

	originalUpdatedAt := scanner.UpdatedAt()
	time.Sleep(10 * time.Millisecond) // Ensure time difference in UpdatedAt

	tests := []struct {
		name          string
		hostname      string
		expectedError error
	}{
		{
			name:          "valid_hostname",
			hostname:      "scanner-host-1",
			expectedError: nil,
		},
		{
			name:          "empty_hostname",
			hostname:      "",
			expectedError: nil,
		},
		{
			name:          "hostname_invalid_chars",
			hostname:      "scanner@host!",
			expectedError: ErrNameInvalidChars,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := scanner.SetHostname(tt.hostname)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.hostname, scanner.Hostname())
			assert.True(t, scanner.UpdatedAt().After(originalUpdatedAt))
		})
	}
}

func TestScanner_SetMetadata(t *testing.T) {
	scannerID := uuid.New()
	groupID := uuid.New()
	scanner, err := NewScanner(scannerID, groupID, "Test Scanner", "1.0.0")
	require.NoError(t, err)

	originalUpdatedAt := scanner.UpdatedAt()
	time.Sleep(10 * time.Millisecond) // Ensure time difference in UpdatedAt

	testMetadata := map[string]any{
		"region":       "us-west",
		"capabilities": []string{"git", "s3"},
		"max_tasks":    10,
	}

	scanner.SetMetadata(nil)
	assert.NotNil(t, scanner.Metadata())
	assert.Empty(t, scanner.Metadata())
	assert.True(t, scanner.UpdatedAt().After(originalUpdatedAt))

	scanner.SetMetadata(testMetadata)
	assert.Equal(t, testMetadata, scanner.Metadata())
}

func TestScanner_UpdateHeartbeat(t *testing.T) {
	scannerID := uuid.New()
	groupID := uuid.New()
	scanner, err := NewScanner(scannerID, groupID, "Test Scanner", "1.0.0")
	require.NoError(t, err)

	originalHeartbeat := scanner.LastHeartbeat()
	originalUpdatedAt := scanner.UpdatedAt()

	// Ensure time passes for a detectable difference.
	time.Sleep(10 * time.Millisecond)

	// Update heartbeat.
	scanner.UpdateHeartbeat()

	// Verify both heartbeat and updatedAt are changed.
	assert.True(t, scanner.LastHeartbeat().After(originalHeartbeat))
	assert.True(t, scanner.UpdatedAt().After(originalUpdatedAt))

	assert.Equal(t, scanner.LastHeartbeat(), scanner.UpdatedAt())
}
