package scanning

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTransition_ValidScannerTransitions(t *testing.T) {
	testCases := []struct {
		name          string
		currentStatus ScannerStatus
		targetStatus  ScannerStatus
		shouldBeValid bool
	}{
		// Self-transitions (always allowed)
		{
			name:          "Unspecified to Unspecified",
			currentStatus: ScannerStatusUnspecified,
			targetStatus:  ScannerStatusUnspecified,
			shouldBeValid: true,
		},
		{
			name:          "Online to Online",
			currentStatus: ScannerStatusOnline,
			targetStatus:  ScannerStatusOnline,
			shouldBeValid: true,
		},
		{
			name:          "Busy to Busy",
			currentStatus: ScannerStatusBusy,
			targetStatus:  ScannerStatusBusy,
			shouldBeValid: true,
		},

		// Common valid transitions
		{
			name:          "Unspecified to Online",
			currentStatus: ScannerStatusUnspecified,
			targetStatus:  ScannerStatusOnline,
			shouldBeValid: true,
		},
		{
			name:          "Online to Busy",
			currentStatus: ScannerStatusOnline,
			targetStatus:  ScannerStatusBusy,
			shouldBeValid: true,
		},
		{
			name:          "Online to Offline",
			currentStatus: ScannerStatusOnline,
			targetStatus:  ScannerStatusOffline,
			shouldBeValid: true,
		},
		{
			name:          "Online to Maintenance",
			currentStatus: ScannerStatusOnline,
			targetStatus:  ScannerStatusMaintenance,
			shouldBeValid: true,
		},
		{
			name:          "Online to Error",
			currentStatus: ScannerStatusOnline,
			targetStatus:  ScannerStatusError,
			shouldBeValid: true,
		},
		{
			name:          "Busy to Online",
			currentStatus: ScannerStatusBusy,
			targetStatus:  ScannerStatusOnline,
			shouldBeValid: true,
		},
		{
			name:          "Busy to Offline",
			currentStatus: ScannerStatusBusy,
			targetStatus:  ScannerStatusOffline,
			shouldBeValid: true,
		},
		{
			name:          "Offline to Online",
			currentStatus: ScannerStatusOffline,
			targetStatus:  ScannerStatusOnline,
			shouldBeValid: true,
		},
		{
			name:          "Offline to Maintenance",
			currentStatus: ScannerStatusOffline,
			targetStatus:  ScannerStatusMaintenance,
			shouldBeValid: true,
		},
		{
			name:          "Maintenance to Online",
			currentStatus: ScannerStatusMaintenance,
			targetStatus:  ScannerStatusOnline,
			shouldBeValid: true,
		},
		{
			name:          "Error to Online",
			currentStatus: ScannerStatusError,
			targetStatus:  ScannerStatusOnline,
			shouldBeValid: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.currentStatus.IsValidTransition(tc.targetStatus)
			assert.Equal(t, tc.shouldBeValid, result)

			err := tc.currentStatus.ValidateTransition(tc.targetStatus)
			if tc.shouldBeValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateTransition_InvalidScannerTransitions(t *testing.T) {
	testCases := []struct {
		name          string
		currentStatus ScannerStatus
		targetStatus  ScannerStatus
		shouldBeValid bool
	}{
		// Invalid transitions
		{
			name:          "Error to Busy",
			currentStatus: ScannerStatusError,
			targetStatus:  ScannerStatusBusy,
			shouldBeValid: false, // Error can't directly go to Busy, must go through Online
		},
		{
			name:          "Error to Unspecified",
			currentStatus: ScannerStatusError,
			targetStatus:  ScannerStatusUnspecified,
			shouldBeValid: false, // Can't go back to Unspecified
		},
		{
			name:          "Offline to Busy",
			currentStatus: ScannerStatusOffline,
			targetStatus:  ScannerStatusBusy,
			shouldBeValid: false, // Offline can't directly go to Busy, must go through Online
		},
		{
			name:          "Maintenance to Busy",
			currentStatus: ScannerStatusMaintenance,
			targetStatus:  ScannerStatusBusy,
			shouldBeValid: false, // Maintenance can't directly go to Busy, must go through Online
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.currentStatus.IsValidTransition(tc.targetStatus)
			assert.Equal(t, tc.shouldBeValid, result)

			err := tc.currentStatus.ValidateTransition(tc.targetStatus)
			if tc.shouldBeValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
