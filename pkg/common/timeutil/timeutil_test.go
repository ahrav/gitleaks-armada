package timeutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRealProvider_Now(t *testing.T) {
	provider := RealProvider{}
	now := provider.Now()

	// Check that it's reasonably close to the current time.
	assert.InEpsilon(t, time.Now().UTC().Unix(), now.Unix(), 10, "Time should be close to current time")
}

func TestMock_Now(t *testing.T) {
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	provider := Mock{CurrentTime: fixedTime}

	// Verify that Now() returns the fixed time.
	assert.Equal(t, fixedTime, provider.Now(), "Mock provider should return the fixed time")
}

func TestMock_Sleep(t *testing.T) {
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	provider := Mock{CurrentTime: fixedTime}

	provider.Sleep(1 * time.Second)
	assert.Equal(t, fixedTime.Add(1*time.Second), provider.Now(), "Time should be advanced by 1 second")
}

func TestMock_SetNow(t *testing.T) {
	initialTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newTime := time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)

	provider := Mock{CurrentTime: initialTime}
	assert.Equal(t, initialTime, provider.Now(), "Initial time should match")

	provider.SetNow(newTime)
	assert.Equal(t, newTime, provider.Now(), "Time should be updated after SetNow")
}

func TestMock_Advance(t *testing.T) {
	initialTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	duration := 1 * time.Hour
	expectedTime := initialTime.Add(duration)

	provider := Mock{CurrentTime: initialTime}
	assert.Equal(t, initialTime, provider.Now(), "Initial time should match")

	provider.Advance(duration)
	assert.Equal(t, expectedTime, provider.Now(), "Time should be advanced by the specified duration")
}

func TestDefault(t *testing.T) {
	provider := Default()

	_, ok := provider.(RealProvider)
	assert.True(t, ok, "Default provider should be a RealProvider")
}

func TestNewMock(t *testing.T) {
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	provider := NewMock(fixedTime)

	assert.Equal(t, fixedTime, provider.Now(), "Mock provider should have the correct time")
}
