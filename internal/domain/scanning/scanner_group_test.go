package scanning

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

func TestNewScannerGroup(t *testing.T) {
	tests := []struct {
		name          string
		groupName     string
		description   string
		expectedError error
	}{
		{
			name:          "valid_group",
			groupName:     "Test Group",
			description:   "This is a test group",
			expectedError: nil,
		},
		{
			name:          "name_too_short",
			groupName:     "",
			description:   "Valid description",
			expectedError: ErrNameTooShort,
		},
		{
			name:          "name_too_long",
			groupName:     strings.Repeat("a", maxNameLength+1),
			description:   "Valid description",
			expectedError: ErrNameTooLong,
		},
		{
			name:          "name_invalid_chars",
			groupName:     "Test@Group!",
			description:   "Valid description",
			expectedError: ErrNameInvalidChars,
		},
		{
			name:          "description_too_long",
			groupName:     "Valid Name",
			description:   strings.Repeat("a", maxDescriptionLength+1),
			expectedError: ErrDescriptionTooLong,
		},
		{
			name:          "empty_description_valid",
			groupName:     "Valid Name",
			description:   "",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group, err := NewScannerGroup(uuid.New(), tt.groupName, tt.description)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, group)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, group)
			assert.Equal(t, tt.groupName, group.Name())
			assert.Equal(t, tt.description, group.Description())
			assert.NotEqual(t, uuid.UUID{}, group.ID())

			// Timestamps should be initialized.
			assert.False(t, group.CreatedAt().IsZero())
			assert.False(t, group.UpdatedAt().IsZero())

			// Created and updated timestamps should be close to now.
			now := time.Now().UTC()
			assert.WithinDuration(t, now, group.CreatedAt(), 1*time.Second)
			assert.WithinDuration(t, now, group.UpdatedAt(), 1*time.Second)
		})
	}
}
