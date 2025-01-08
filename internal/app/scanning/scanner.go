package scanning

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
)

type SecretScanner interface {
	// Scan a given ScanTask.
	Scan(ctx context.Context, task *dtos.ScanRequest) error
}
