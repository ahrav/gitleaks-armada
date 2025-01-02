package domain

// ScanProgress provides information about an ongoing scan operation.
type ScanProgress struct {
	TaskID          string
	PercentComplete float32           // Overall scan progress (0-100)
	ItemsProcessed  int64             // Number of items (e.g., files) processed
	TotalItems      int64             // Total number of items to process
	Metadata        map[string]string // Additional progress information
}
