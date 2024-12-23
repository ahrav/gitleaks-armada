// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package db

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

type EnumerationStatus string

const (
	EnumerationStatusInitialized EnumerationStatus = "initialized"
	EnumerationStatusInProgress  EnumerationStatus = "in_progress"
	EnumerationStatusCompleted   EnumerationStatus = "completed"
	EnumerationStatusFailed      EnumerationStatus = "failed"
)

func (e *EnumerationStatus) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = EnumerationStatus(s)
	case string:
		*e = EnumerationStatus(s)
	default:
		return fmt.Errorf("unsupported scan type for EnumerationStatus: %T", src)
	}
	return nil
}

type NullEnumerationStatus struct {
	EnumerationStatus EnumerationStatus
	Valid             bool // Valid is true if EnumerationStatus is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullEnumerationStatus) Scan(value interface{}) error {
	if value == nil {
		ns.EnumerationStatus, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.EnumerationStatus.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullEnumerationStatus) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.EnumerationStatus), nil
}

type Checkpoint struct {
	ID        int64
	TargetID  string
	Data      json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

type EnumerationState struct {
	ID               int32
	SessionID        string
	SourceType       string
	Config           json.RawMessage
	LastCheckpointID sql.NullInt64
	Status           EnumerationStatus
	CreatedAt        time.Time
	UpdatedAt        time.Time
}