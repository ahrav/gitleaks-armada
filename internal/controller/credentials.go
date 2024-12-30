package controller

import (
	"fmt"

	"github.com/ahrav/gitleaks-armada/pkg/config"
	"github.com/ahrav/gitleaks-armada/pkg/messaging"
)

// CredentialStore provides centralized access to authentication configurations.
// It maps auth references to their corresponding credentials.
type CredentialStore struct {
	credentials map[string]*messaging.TaskCredentials
}

// NewCredentialStore initializes a store from a map of auth configurations.
// It validates and transforms each config into concrete credentials.
func NewCredentialStore(authConfigs map[string]config.AuthConfig) (*CredentialStore, error) {
	store := &CredentialStore{
		credentials: make(map[string]*messaging.TaskCredentials),
	}

	for name, auth := range authConfigs {
		creds, err := messaging.CreateCredentials(messaging.CredentialType(auth.Type), auth.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create credentials for %s: %w", name, err)
		}
		store.credentials[name] = creds
	}

	return store, nil
}

// GetCredentials looks up credentials by their reference name.
// Returns an error if the reference doesn't exist.
func (s *CredentialStore) GetCredentials(authRef string) (*messaging.TaskCredentials, error) {
	creds, ok := s.credentials[authRef]
	if !ok {
		return nil, fmt.Errorf("no credentials found for auth_ref: %s", authRef)
	}
	return creds, nil
}
