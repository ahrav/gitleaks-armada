package enumeration

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/enumeration/github"
	"github.com/ahrav/gitleaks-armada/internal/app/enumeration/shared"
	"github.com/ahrav/gitleaks-armada/internal/app/enumeration/url"
	"github.com/ahrav/gitleaks-armada/internal/config"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	types "github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// EnumeratorFactory creates TargetEnumerators for different data sources.
// It encapsulates the logic for instantiating appropriate enumerators based on
// target configuration and authentication details.
type EnumeratorFactory interface {
	// CreateEnumerator constructs a new TargetEnumerator for the given target
	// specification and authentication configuration.
	CreateEnumerator(ctx context.Context, target config.TargetSpec, creds *domain.TaskCredentials) (shared.TargetEnumerator, error)
}

// enumerationFactory creates target enumerators with required dependencies.
type enumerationFactory struct {
	controllerID string

	httpClient *http.Client

	logger *logger.Logger
	tracer trace.Tracer
}

// NewEnumerationFactory creates a new factory for instantiating target enumerators.
// It takes the required dependencies needed by all enumerator types.
func NewEnumerationFactory(
	controllerID string,
	httpClient *http.Client,
	logger *logger.Logger,
	tracer trace.Tracer,
) EnumeratorFactory {
	return &enumerationFactory{
		controllerID: controllerID,
		httpClient:   httpClient,
		logger:       logger,
		tracer:       tracer,
	}
}

// CreateEnumerator constructs a target enumerator based on the provided configuration.
// It handles authentication and creates source-specific enumerators (e.g., GitHub, S3).
// Returns an error if the target configuration is invalid or required credentials are missing.
// TODO: Revist the use of this factory it's still a bit wonky with the credential store.
func (f *enumerationFactory) CreateEnumerator(
	ctx context.Context, target config.TargetSpec, creds *domain.TaskCredentials) (shared.TargetEnumerator, error) {
	ctx, span := f.tracer.Start(ctx, "enumeration_factory.create_enumerator",
		trace.WithAttributes(
			attribute.String("controller_id", f.controllerID),
			attribute.String("source_type", string(target.SourceType)),
			attribute.String("auth_ref", target.AuthRef),
		))
	defer span.End()

	switch target.SourceType {
	case types.SourceTypeGitHub:
		githubSpan := trace.SpanFromContext(ctx)
		defer githubSpan.End()

		if target.GitHub == nil {
			githubSpan.RecordError(fmt.Errorf("github target configuration is missing"))
			return nil, fmt.Errorf("github target configuration is missing")
		}

		ghClient, err := github.NewGraphQLClient(f.controllerID, f.httpClient, creds, f.logger, f.tracer)
		if err != nil {
			githubSpan.RecordError(err)
			return nil, fmt.Errorf("failed to create GitHub client: %w", err)
		}

		githubSpan.AddEvent("github_client_created")

		return github.NewEnumerator(
			f.controllerID,
			ghClient,
			target.GitHub,
			f.logger,
			f.tracer,
		), nil
	case types.SourceTypeURL:
		urlSpan := trace.SpanFromContext(ctx)
		defer urlSpan.End()

		if target.URL == nil {
			urlSpan.RecordError(fmt.Errorf("url target configuration is missing"))
			return nil, fmt.Errorf("url target configuration is missing")
		}

		return url.NewEnumerator(
			f.controllerID,
			target.URL,
			f.logger,
			f.tracer,
		), nil
	case types.SourceTypeS3:
		// TODO: Implement S3 enumerator.
		panic("not implemented")
	default:
		err := fmt.Errorf("unsupported source type: %s", target.SourceType)
		span.RecordError(err)
		return nil, err
	}
}
