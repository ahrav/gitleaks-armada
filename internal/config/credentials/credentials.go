package credentials

import (
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
)

type Store interface {
	GetCredentials(authRef string) (*enumeration.TaskCredentials, error)
}
