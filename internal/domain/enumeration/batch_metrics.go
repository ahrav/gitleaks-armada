package enumeration

import (
	"encoding/json"
	"fmt"
)

// BatchMetrics is a value object that tracks quantitative measures for a batch.
// It maintains counts of processed items and expected items, along with any error
// details if the batch fails.
type BatchMetrics struct {
	expectedItems  int
	itemsProcessed int
	errorDetails   string
}

// NewBatchMetrics creates a new BatchMetrics instance with the specified number
// of expected items.
func NewBatchMetrics(expectedItems int) *BatchMetrics {
	return &BatchMetrics{expectedItems: expectedItems}
}

// ReconstructBatchMetrics creates a BatchMetrics instance from persisted data.
func ReconstructBatchMetrics(
	expectedItems int,
	itemsProcessed int,
	errorDetails string,
) *BatchMetrics {
	return &BatchMetrics{
		expectedItems:  expectedItems,
		itemsProcessed: itemsProcessed,
		errorDetails:   errorDetails,
	}
}

// ExpectedItems returns the number of expected items in the batch.
func (bm *BatchMetrics) ExpectedItems() int { return bm.expectedItems }

// ItemsProcessed returns the number of items processed in the batch.
func (bm *BatchMetrics) ItemsProcessed() int { return bm.itemsProcessed }

// ErrorDetails returns the error details for the batch.
func (bm *BatchMetrics) ErrorDetails() string { return bm.errorDetails }

// MarshalJSON serializes BatchMetrics to JSON.
func (bm *BatchMetrics) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ExpectedItems  int    `json:"expected_items"`
		ItemsProcessed int    `json:"items_processed"`
		ErrorDetails   string `json:"error_details,omitempty"`
	}{
		ExpectedItems:  bm.expectedItems,
		ItemsProcessed: bm.itemsProcessed,
		ErrorDetails:   bm.errorDetails,
	})
}

// UnmarshalJSON deserializes JSON into BatchMetrics.
func (bm *BatchMetrics) UnmarshalJSON(data []byte) error {
	aux := &struct {
		ExpectedItems  int    `json:"expected_items"`
		ItemsProcessed int    `json:"items_processed"`
		ErrorDetails   string `json:"error_details,omitempty"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	bm.expectedItems = aux.ExpectedItems
	bm.itemsProcessed = aux.ItemsProcessed
	bm.errorDetails = aux.ErrorDetails

	return nil
}

// MarkSuccessful updates the number of processed items. It returns an error if
// the number of processed items exceeds the expected count.
func (bm *BatchMetrics) MarkSuccessful(itemsProcessed int) error {
	if itemsProcessed > bm.expectedItems {
		return fmt.Errorf("processed items (%d) exceeds expected items (%d)",
			itemsProcessed, bm.expectedItems)
	}
	bm.itemsProcessed = itemsProcessed
	return nil
}

// MarkFailed records the error details for a failed batch.
func (bm *BatchMetrics) MarkFailed(err error) {
	if err != nil {
		bm.errorDetails = err.Error()
	}
}

// CompletionPercentage calculates the percentage of items processed.
// Returns 0 if no items were expected.
func (bm *BatchMetrics) CompletionPercentage() float64 {
	if bm.expectedItems == 0 {
		return 0
	}
	return float64(bm.itemsProcessed) / float64(bm.expectedItems) * 100
}

// HasError returns true if error details are present.
func (bm *BatchMetrics) HasError() bool { return bm.errorDetails != "" }
