// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package db

import (
	"database/sql/driver"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
)

type BatchStatus string

const (
	BatchStatusSUCCEEDED          BatchStatus = "SUCCEEDED"
	BatchStatusFAILED             BatchStatus = "FAILED"
	BatchStatusPARTIALLYCOMPLETED BatchStatus = "PARTIALLY_COMPLETED"
	BatchStatusINPROGRESS         BatchStatus = "IN_PROGRESS"
)

func (e *BatchStatus) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = BatchStatus(s)
	case string:
		*e = BatchStatus(s)
	default:
		return fmt.Errorf("unsupported scan type for BatchStatus: %T", src)
	}
	return nil
}

type NullBatchStatus struct {
	BatchStatus BatchStatus
	Valid       bool // Valid is true if BatchStatus is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullBatchStatus) Scan(value interface{}) error {
	if value == nil {
		ns.BatchStatus, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.BatchStatus.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullBatchStatus) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.BatchStatus), nil
}

type EnumerationStatus string

const (
	EnumerationStatusINITIALIZED        EnumerationStatus = "INITIALIZED"
	EnumerationStatusINPROGRESS         EnumerationStatus = "IN_PROGRESS"
	EnumerationStatusCOMPLETED          EnumerationStatus = "COMPLETED"
	EnumerationStatusFAILED             EnumerationStatus = "FAILED"
	EnumerationStatusSTALLED            EnumerationStatus = "STALLED"
	EnumerationStatusPARTIALLYCOMPLETED EnumerationStatus = "PARTIALLY_COMPLETED"
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

type ScanJobStatus string

const (
	ScanJobStatusQUEUED      ScanJobStatus = "QUEUED"
	ScanJobStatusENUMERATING ScanJobStatus = "ENUMERATING"
	ScanJobStatusRUNNING     ScanJobStatus = "RUNNING"
	ScanJobStatusPAUSING     ScanJobStatus = "PAUSING"
	ScanJobStatusPAUSED      ScanJobStatus = "PAUSED"
	ScanJobStatusCOMPLETED   ScanJobStatus = "COMPLETED"
	ScanJobStatusFAILED      ScanJobStatus = "FAILED"
)

func (e *ScanJobStatus) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ScanJobStatus(s)
	case string:
		*e = ScanJobStatus(s)
	default:
		return fmt.Errorf("unsupported scan type for ScanJobStatus: %T", src)
	}
	return nil
}

type NullScanJobStatus struct {
	ScanJobStatus ScanJobStatus
	Valid         bool // Valid is true if ScanJobStatus is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullScanJobStatus) Scan(value interface{}) error {
	if value == nil {
		ns.ScanJobStatus, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.ScanJobStatus.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullScanJobStatus) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.ScanJobStatus), nil
}

type ScanTaskStallReason string

const (
	ScanTaskStallReasonNOPROGRESS    ScanTaskStallReason = "NO_PROGRESS"
	ScanTaskStallReasonLOWTHROUGHPUT ScanTaskStallReason = "LOW_THROUGHPUT"
	ScanTaskStallReasonHIGHERRORS    ScanTaskStallReason = "HIGH_ERRORS"
)

func (e *ScanTaskStallReason) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ScanTaskStallReason(s)
	case string:
		*e = ScanTaskStallReason(s)
	default:
		return fmt.Errorf("unsupported scan type for ScanTaskStallReason: %T", src)
	}
	return nil
}

type NullScanTaskStallReason struct {
	ScanTaskStallReason ScanTaskStallReason
	Valid               bool // Valid is true if ScanTaskStallReason is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullScanTaskStallReason) Scan(value interface{}) error {
	if value == nil {
		ns.ScanTaskStallReason, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.ScanTaskStallReason.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullScanTaskStallReason) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.ScanTaskStallReason), nil
}

type ScanTaskStatus string

const (
	ScanTaskStatusPENDING    ScanTaskStatus = "PENDING"
	ScanTaskStatusINPROGRESS ScanTaskStatus = "IN_PROGRESS"
	ScanTaskStatusPAUSED     ScanTaskStatus = "PAUSED"
	ScanTaskStatusCOMPLETED  ScanTaskStatus = "COMPLETED"
	ScanTaskStatusFAILED     ScanTaskStatus = "FAILED"
	ScanTaskStatusSTALE      ScanTaskStatus = "STALE"
)

func (e *ScanTaskStatus) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ScanTaskStatus(s)
	case string:
		*e = ScanTaskStatus(s)
	default:
		return fmt.Errorf("unsupported scan type for ScanTaskStatus: %T", src)
	}
	return nil
}

type NullScanTaskStatus struct {
	ScanTaskStatus ScanTaskStatus
	Valid          bool // Valid is true if ScanTaskStatus is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullScanTaskStatus) Scan(value interface{}) error {
	if value == nil {
		ns.ScanTaskStatus, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.ScanTaskStatus.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullScanTaskStatus) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.ScanTaskStatus), nil
}

type Allowlist struct {
	ID             int64
	RuleID         int64
	Description    pgtype.Text
	MatchCondition string
	RegexTarget    pgtype.Text
	CreatedAt      pgtype.Timestamptz
	UpdatedAt      pgtype.Timestamptz
}

type AllowlistCommit struct {
	ID          int64
	AllowlistID int64
	Commit      string
	CreatedAt   pgtype.Timestamptz
}

type AllowlistPath struct {
	ID          int64
	AllowlistID int64
	Path        string
	CreatedAt   pgtype.Timestamptz
}

type AllowlistRegex struct {
	ID          int64
	AllowlistID int64
	Regex       string
	CreatedAt   pgtype.Timestamptz
}

type AllowlistStopword struct {
	ID          int64
	AllowlistID int64
	Stopword    string
	CreatedAt   pgtype.Timestamptz
}

type Checkpoint struct {
	ID        int64
	TargetID  pgtype.UUID
	Data      []byte
	CreatedAt pgtype.Timestamptz
	UpdatedAt pgtype.Timestamptz
}

type EnumerationBatch struct {
	BatchID        pgtype.UUID
	SessionID      pgtype.UUID
	Status         BatchStatus
	CheckpointID   pgtype.Int8
	StartedAt      pgtype.Timestamptz
	CompletedAt    pgtype.Timestamptz
	LastUpdate     pgtype.Timestamptz
	ItemsProcessed int32
	ExpectedItems  int32
	ErrorDetails   pgtype.Text
	CreatedAt      pgtype.Timestamptz
	UpdatedAt      pgtype.Timestamptz
}

type EnumerationSessionMetric struct {
	SessionID      pgtype.UUID
	TotalBatches   int32
	FailedBatches  int32
	ItemsFound     int32
	ItemsProcessed int32
	CreatedAt      pgtype.Timestamptz
	UpdatedAt      pgtype.Timestamptz
}

type EnumerationSessionState struct {
	SessionID        pgtype.UUID
	SourceType       string
	Config           []byte
	LastCheckpointID pgtype.Int8
	Status           EnumerationStatus
	FailureReason    pgtype.Text
	StartedAt        pgtype.Timestamptz
	CompletedAt      pgtype.Timestamptz
	LastUpdate       pgtype.Timestamptz
	CreatedAt        pgtype.Timestamptz
	UpdatedAt        pgtype.Timestamptz
}

type EnumerationTask struct {
	TaskID      pgtype.UUID
	SessionID   pgtype.UUID
	ResourceUri string
	Metadata    []byte
	CreatedAt   pgtype.Timestamptz
	UpdatedAt   pgtype.Timestamptz
}

type Finding struct {
	ID           pgtype.UUID
	ScanJobID    pgtype.UUID
	RuleID       int64
	ScanTargetID pgtype.UUID
	Fingerprint  string
	FilePath     pgtype.Text
	LineNumber   pgtype.Int4
	Line         pgtype.Text
	Match        pgtype.Text
	AuthorEmail  pgtype.Text
	RawFinding   []byte
	CreatedAt    pgtype.Timestamptz
}

type GithubRepository struct {
	ID        int64
	Name      string
	Url       string
	IsActive  bool
	Metadata  []byte
	CreatedAt pgtype.Timestamptz
	UpdatedAt pgtype.Timestamptz
}

type JobMetricsCheckpoint struct {
	JobID           pgtype.UUID
	PartitionID     int32
	PartitionOffset int64
	LastProcessedAt pgtype.Timestamptz
}

type Rule struct {
	ID          int64
	RuleID      string
	Description pgtype.Text
	Entropy     pgtype.Float8
	SecretGroup pgtype.Int4
	Regex       string
	Path        pgtype.Text
	Tags        []string
	Keywords    []string
	CreatedAt   pgtype.Timestamptz
	UpdatedAt   pgtype.Timestamptz
}

type ScanJob struct {
	JobID     pgtype.UUID
	Status    ScanJobStatus
	StartTime pgtype.Timestamptz
	EndTime   pgtype.Timestamptz
	CreatedAt pgtype.Timestamptz
	UpdatedAt pgtype.Timestamptz
}

type ScanJobMetric struct {
	JobID           pgtype.UUID
	TotalTasks      int32
	PendingTasks    int32
	InProgressTasks int32
	CompletedTasks  int32
	FailedTasks     int32
	StaleTasks      int32
	UpdatedAt       pgtype.Timestamptz
	CreatedAt       pgtype.Timestamptz
}

type ScanJobTarget struct {
	JobID        pgtype.UUID
	ScanTargetID pgtype.UUID
}

type ScanTarget struct {
	ID           pgtype.UUID
	Name         string
	TargetType   string
	TargetID     int64
	LastScanTime pgtype.Timestamptz
	Metadata     []byte
	CreatedAt    pgtype.Timestamptz
	UpdatedAt    pgtype.Timestamptz
}

type ScanTask struct {
	TaskID            pgtype.UUID
	JobID             pgtype.UUID
	OwnerControllerID string
	Status            ScanTaskStatus
	ResourceUri       string
	LastSequenceNum   int64
	LastHeartbeatAt   pgtype.Timestamptz
	StartTime         pgtype.Timestamptz
	EndTime           pgtype.Timestamptz
	ItemsProcessed    int64
	ProgressDetails   []byte
	LastCheckpoint    []byte
	StallReason       NullScanTaskStallReason
	RecoveryAttempts  int32
	StalledAt         pgtype.Timestamptz
	PausedAt          pgtype.Timestamptz
	CreatedAt         pgtype.Timestamptz
	UpdatedAt         pgtype.Timestamptz
}

type Task struct {
	TaskID     pgtype.UUID
	SourceType string
}

type Url struct {
	ID        int64
	Url       string
	Metadata  []byte
	CreatedAt pgtype.Timestamptz
	UpdatedAt pgtype.Timestamptz
}
