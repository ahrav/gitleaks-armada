// Package timeutil provides time-related utilities and abstractions.
// It facilitates easier testing of time-dependent code and standardizes
// time-related operations across the application.
package timeutil

import "time"

// Provider defines an interface for time operations,
// allowing for easier testing by providing a way to mock time.
type Provider interface {
	// Now returns the current time.
	Now() time.Time
}

// RealProvider is the default implementation of Provider that
// provides access to the actual system time.
type RealProvider struct{}

// Now returns the current time in UTC.
func (RealProvider) Now() time.Time { return time.Now().UTC() }

// Mock is an implementation of Provider used for testing,
// allowing tests to control what time is returned.
type Mock struct{ CurrentTime time.Time }

// Now returns the preset time.
func (m Mock) Now() time.Time { return m.CurrentTime }

// SetNow directly sets the current time to the provided time.
func (m *Mock) SetNow(t time.Time) { m.CurrentTime = t }

// Advance moves the mock time forward by the specified duration.
func (m *Mock) Advance(d time.Duration) { m.CurrentTime = m.CurrentTime.Add(d) }

// Default returns a Provider implementation that uses the real system time.
func Default() Provider { return RealProvider{} }

// NewMock creates a new mock time provider with the specified time.
func NewMock(t time.Time) *Mock { return &Mock{CurrentTime: t} }
