package enumeration

import "time"

// Checkpoint is an entity object that stores progress information for resumable target enumeration.
// It enables reliable scanning of large data sources by tracking the last successfully processed position.
// As an entity, it has a unique identity (ID) that persists across state changes and is mutable over time
// through its Data and UpdatedAt fields.
type Checkpoint struct {
	ID        int64          `json:"id"`
	TargetID  string         `json:"target_id"`
	Data      map[string]any `json:"data"`
	UpdatedAt time.Time      `json:"updated_at"`
}
