package enumeration

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/task"
)

// EnumeratorFactory creates TargetEnumerators for different data sources.
// It encapsulates the logic for instantiating appropriate enumerators based on
// target configuration and authentication details.
type EnumeratorFactory interface {
	// CreateEnumerator constructs a new TargetEnumerator for the given target
	// specification and authentication configuration.
	CreateEnumerator(target config.TargetSpec, auth map[string]config.AuthConfig) (TargetEnumerator, error)
}

// enumerationFactory creates target enumerators with required dependencies.
type enumerationFactory struct {
	httpClient *http.Client
	credStore  *task.CredentialStore
	tracer     trace.Tracer
}

// NewEnumerationFactory creates a new factory for instantiating target enumerators.
// It takes the required dependencies needed by all enumerator types.
func NewEnumerationFactory(
	httpClient *http.Client,
	credStore *task.CredentialStore,
	tracer trace.Tracer,
) EnumeratorFactory {
	return &enumerationFactory{
		httpClient: httpClient,
		tracer:     tracer,
	}
}

// CreateEnumerator constructs a target enumerator based on the provided configuration.
// It handles authentication and creates source-specific enumerators (e.g., GitHub, S3).
// Returns an error if the target configuration is invalid or required credentials are missing.
// TODO: Revist the use of this factory it's still a bit wonky with the credential store.
func (f *enumerationFactory) CreateEnumerator(target config.TargetSpec, auth map[string]config.AuthConfig) (TargetEnumerator, error) {
	ctx := context.Background()
	ctx, span := f.tracer.Start(ctx, "factory.CreateEnumerator",
		trace.WithAttributes(
			attribute.String("source_type", string(target.SourceType)),
			attribute.String("auth_ref", target.AuthRef),
		))
	defer span.End()

	if f.credStore == nil {
		var err error
		_, credSpan := f.tracer.Start(ctx, "factory.createCredentialStore")
		f.credStore, err = task.NewCredentialStore(auth)
		if err != nil {
			credSpan.RecordError(err)
			credSpan.End()
			return nil, fmt.Errorf("failed to create credential store: %w", err)
		}
		credSpan.End()
	}

	creds, err := f.credStore.GetCredentials(target.AuthRef)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	switch target.SourceType {
	case config.SourceTypeGitHub:
		// Ensure GitHub-specific configuration exists.
		if target.GitHub == nil {
			span.RecordError(fmt.Errorf("github target configuration is missing"))
			return nil, fmt.Errorf("github target configuration is missing")
		}

		_, ghSpan := f.tracer.Start(ctx, "factory.createGitHubClient")
		ghClient, err := NewGitHubClient(f.httpClient, creds, f.tracer)
		if err != nil {
			ghSpan.RecordError(err)
			ghSpan.End()
			return nil, fmt.Errorf("failed to create GitHub client: %w", err)
		}
		ghSpan.End()

		return NewGitHubEnumerator(
			ghClient,
			creds,
			target.GitHub,
			f.tracer,
		), nil
	case config.SourceTypeS3:
		span.SetAttributes(attribute.String("source_type", "s3"))
		// TODO: Implement S3 enumerator.
	default:
		err := fmt.Errorf("unsupported source type: %s", target.SourceType)
		span.RecordError(err)
		return nil, err
	}

	return nil, nil
}
