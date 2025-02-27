package enumeration

import (
	"encoding/json"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Checkpoint is an entity object that stores progress information for resumable target enumeration.
// It enables reliable scanning of large data sources by tracking the last successfully processed position.
// As an entity, it has a unique identity (ID) that persists across state changes and is mutable over time
// through its Data and UpdatedAt fields.
type Checkpoint struct {
	// Identity.
	id       int64
	targetID uuid.UUID

	// State/Metadata.
	data      map[string]any
	updatedAt time.Time
}

// NewCheckpoint creates a new Checkpoint entity with a persistent ID. The ID is provided by the caller,
// typically from a persistence layer, to maintain entity identity across state changes. The checkpoint
// tracks enumeration progress for a specific target using arbitrary data.
func NewCheckpoint(id int64, targetID uuid.UUID, data map[string]any) *Checkpoint {
	return &Checkpoint{
		id:        id,
		targetID:  targetID,
		data:      data,
		updatedAt: time.Now(),
	}
}

// NewTemporaryCheckpoint creates a Checkpoint without a persistent ID for use in transient operations.
// This allows checkpoints to be created and manipulated in memory before being persisted. Once
// persisted, a proper entity ID should be assigned via NewCheckpoint.
func NewTemporaryCheckpoint(targetID uuid.UUID, data map[string]any) *Checkpoint {
	return &Checkpoint{
		targetID:  targetID,
		data:      data,
		updatedAt: time.Now(),
	}
}

// Getters for Checkpoint.
func (c *Checkpoint) ID() int64            { return c.id }
func (c *Checkpoint) TargetID() uuid.UUID  { return c.targetID }
func (c *Checkpoint) Data() map[string]any { return c.data }
func (c *Checkpoint) UpdatedAt() time.Time { return c.updatedAt }

// IsTemporary returns true if the checkpoint has no ID.
func (c *Checkpoint) IsTemporary() bool { return c.id == 0 }

// Setters for Checkpoint.

// SetID updates the checkpoint's ID after persistence. This should only be used
// to set the ID of a temporary checkpoint after it has been persisted.
// It will panic if called on an already-persisted checkpoint to prevent ID mutations.
func (c *Checkpoint) SetID(id int64) {
	if c.id != 0 {
		panic("attempting to modify ID of a persisted checkpoint")
	}
	c.id = id
}

// MarshalJSON serializes the Checkpoint object into a JSON byte array.
func (c *Checkpoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID        int64          `json:"id"`
		TargetID  string         `json:"target_id"`
		Data      map[string]any `json:"data"`
		UpdatedAt time.Time      `json:"updated_at"`
	}{
		ID:        c.id,
		TargetID:  c.targetID.String(),
		Data:      c.data,
		UpdatedAt: c.updatedAt,
	})
}

// UnmarshalJSON deserializes JSON data into a Checkpoint object.
func (c *Checkpoint) UnmarshalJSON(data []byte) error {
	aux := &struct {
		ID        int64          `json:"id"`
		TargetID  string         `json:"target_id"`
		Data      map[string]any `json:"data"`
		UpdatedAt time.Time      `json:"updated_at"`
	}{
		ID:        c.id,
		TargetID:  c.targetID.String(),
		Data:      c.data,
		UpdatedAt: c.updatedAt,
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	c.id = aux.ID
	c.targetID = uuid.MustParse(aux.TargetID)
	c.data = aux.Data
	c.updatedAt = aux.UpdatedAt

	return nil
}
