package serializationerrors

import "fmt"

// ErrNilEvent indicates that a nil event was provided for serialization/deserialization
type ErrNilEvent struct{ EventType string }

func (e ErrNilEvent) Error() string { return fmt.Sprintf("nil %s event", e.EventType) }

// ErrInvalidUUID indicates that a UUID field could not be parsed
type ErrInvalidUUID struct {
	Field string
	Err   error
}

func (e ErrInvalidUUID) Error() string { return fmt.Sprintf("invalid %s: %v", e.Field, e.Err) }

func (e ErrInvalidUUID) Unwrap() error { return e.Err }

// ErrInvalidSourceType indicates that an invalid source type was provided
type ErrInvalidSourceType struct{ Value any }

func (e ErrInvalidSourceType) Error() string { return fmt.Sprintf("invalid source type: %v", e.Value) }
