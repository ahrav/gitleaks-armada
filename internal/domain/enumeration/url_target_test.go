package enumeration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewURLTarget(t *testing.T) {
	metadata := map[string]any{"key": "value"}
	url := "http://example.com"

	target, err := NewURLTarget(url, metadata)
	assert.NoError(t, err)
	assert.NotNil(t, target)
	assert.Equal(t, url, target.URL())
	assert.Equal(t, metadata, target.Metadata())
	assert.NotNil(t, target.timeline)
}

func TestNewURLTarget_EmptyURL(t *testing.T) {
	metadata := map[string]any{"key": "value"}

	target, err := NewURLTarget("", metadata)
	assert.Error(t, err)
	assert.Nil(t, target)
}

func TestReconstructURLTarget(t *testing.T) {
	// Arrange: Set up the input parameters for reconstruction
	id := int64(1)
	url := "http://example.com"
	metadata := map[string]any{"key": "value"}

	// Use a fixed time for testing
	fixedTime := time.Date(2023, 10, 1, 12, 0, 0, 0, time.UTC)
	mockProvider := mockTimeProvider{current: fixedTime}
	timeline := NewTimeline(&mockProvider)

	// Act: Call the ReconstructURLTarget function
	target := ReconstructURLTarget(id, url, metadata, timeline)

	// Assert: Verify that the target is reconstructed correctly
	assert.NotNil(t, target)
	assert.Equal(t, id, target.ID())
	assert.Equal(t, url, target.URL())
	assert.Equal(t, metadata, target.Metadata())
	assert.Equal(t, fixedTime, target.CreatedAt())
	assert.Equal(t, fixedTime, target.UpdatedAt())
}

func TestURLTarget_UpdateURL(t *testing.T) {
	metadata := map[string]any{"key": "value"}
	url := "http://example.com"
	target, _ := NewURLTarget(url, metadata)

	newURL := "http://newexample.com"
	err := target.UpdateURL(newURL)
	assert.NoError(t, err)
	assert.Equal(t, newURL, target.URL())
}

func TestURLTarget_UpdateURL_Empty(t *testing.T) {
	metadata := map[string]any{"key": "value"}
	url := "http://example.com"
	target, _ := NewURLTarget(url, metadata)

	err := target.UpdateURL("")
	assert.Error(t, err)
	assert.Equal(t, url, target.URL()) // URL should remain unchanged
}

func TestURLTarget_SetID(t *testing.T) {
	metadata := map[string]any{"key": "value"}
	url := "http://example.com"
	target, _ := NewURLTarget(url, metadata)

	target.SetID(42)
	assert.Equal(t, int64(42), target.ID())
}

func TestURLTarget_Timeline(t *testing.T) {
	metadata := map[string]any{"key": "value"}
	url := "http://example.com"
	target, _ := NewURLTarget(url, metadata)

	createdAt := target.CreatedAt()
	updatedAt := target.UpdatedAt()

	assert.WithinDuration(t, time.Now(), createdAt, time.Second)
	assert.WithinDuration(t, time.Now(), updatedAt, time.Second)

	// Simulate an update
	target.UpdateURL("http://updated.com")
	assert.True(t, target.UpdatedAt().After(updatedAt))
}
