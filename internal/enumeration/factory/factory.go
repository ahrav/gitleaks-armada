// Package factory provides functionality for creating target enumerators based on configuration.
package factory

import (
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/enumeration/github"
	"github.com/ahrav/gitleaks-armada/pkg/config"
	"github.com/ahrav/gitleaks-armada/pkg/domain/enumeration"
)

// enumerationFactory creates target enumerators with required dependencies.
type enumerationFactory struct {
	httpClient       *http.Client
	credStore        *enumeration.CredentialStore
	enumerationStore enumeration.EnumerationStateStorage
	tracer           trace.Tracer
}

// NewEnumerationFactory creates a new factory for instantiating target enumerators.
// It takes the required dependencies needed by all enumerator types.
func NewEnumerationFactory(
	httpClient *http.Client,
	credStore *enumeration.CredentialStore,
	enumStore enumeration.EnumerationStateStorage,
	tracer trace.Tracer,
) enumeration.EnumeratorFactory {
	return &enumerationFactory{
		httpClient:       httpClient,
		enumerationStore: enumStore,
		tracer:           tracer,
	}
}

// CreateEnumerator constructs a target enumerator based on the provided configuration.
// It handles authentication and creates source-specific enumerators (e.g., GitHub, S3).
// Returns an error if the target configuration is invalid or required credentials are missing.
func (f *enumerationFactory) CreateEnumerator(target config.TargetSpec, auth map[string]config.AuthConfig) (enumeration.TargetEnumerator, error) {
	if f.credStore == nil {
		var err error
		f.credStore, err = enumeration.NewCredentialStore(auth)
		if err != nil {
			return nil, fmt.Errorf("failed to create credential store: %w", err)
		}
	}

	creds, err := f.credStore.GetCredentials(target.AuthRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	switch target.SourceType {
	case config.SourceTypeGitHub:
		// Ensure GitHub-specific configuration exists
		if target.GitHub == nil {
			return nil, fmt.Errorf("github target configuration is missing")
		}
		ghClient, err := github.NewGitHubClient(f.httpClient, creds)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitHub client: %w", err)
		}
		return github.NewGitHubEnumerator(
			ghClient,
			creds,
			f.enumerationStore,
			target.GitHub,
			f.tracer,
		), nil
	case config.SourceTypeS3:
		// build S3Enumerator
		// ...
	default:
		return nil, fmt.Errorf("unsupported source type: %s", target.SourceType)
	}

	return nil, nil
}
