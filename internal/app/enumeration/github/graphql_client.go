package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/pkg/common"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// GraphQLClient is a wrapper around the GitHub GraphQL API client with rate limiting and tracing.
type GraphQLClient struct {
	controllerID string

	httpClient  *http.Client
	token       string
	rateLimiter *common.RateLimiter

	logger *logger.Logger
	tracer trace.Tracer
}

// NewGraphQLClient creates a new GraphQL client with rate limiting.
func NewGraphQLClient(
	controllerID string,
	httpClient *http.Client,
	creds *domain.TaskCredentials,
	logger *logger.Logger,
	tracer trace.Tracer,
) (*GraphQLClient, error) {
	// TODO: This is a tamp solution. I need to clean this up.
	var token string
	if creds.Type == domain.CredentialTypeGitHub {
		var err error
		token, err = extractToken(creds)
		if err != nil {
			return nil, fmt.Errorf("failed to extract GitHub token: %w", err)
		}
	}

	// GitHub's default rate limit is 5000 requests per hour.
	// Setting initial rate to 4500/hour (1.25/second) to be conservative.
	return &GraphQLClient{
		controllerID: controllerID,
		httpClient:   httpClient,
		rateLimiter:  common.NewRateLimiter(1.25, 5),
		token:        token,
		logger:       logger.With("component", "github_graphql_client"),
		tracer:       tracer,
	}, nil
}

// extractToken retrieves and validates the authentication token from GitHub credentials.
// It returns an error if the credentials are not GitHub type or if the token is missing.
func extractToken(creds *domain.TaskCredentials) (string, error) {
	if creds.Type != domain.CredentialTypeGitHub && creds.Type != domain.CredentialTypeUnauthenticated {
		return "", fmt.Errorf("expected github credentials, got %s", creds.Type)
	}

	tokenVal, ok := creds.Values["auth_token"].(string)
	if !ok || tokenVal == "" {
		return "", fmt.Errorf("auth_token missing or empty in GitHub credentials")
	}
	return tokenVal, nil
}

// repositoryResponse represents the structure of GitHub's GraphQL API response for repository queries.
// It includes both the repository data and any potential error messages.
type repositoryResponse struct {
	Data struct {
		Organization struct {
			Repositories struct {
				Nodes []struct {
					Name string `json:"name"`
				} `json:"nodes"`
				PageInfo struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
			} `json:"repositories"`
		} `json:"organization"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// ListRepositories retrieves a paginated list of repository names from a GitHub organization
// using the GraphQL API. It fetches repositories in batches of 100 and accepts an optional
// cursor for continuation.
func (c *GraphQLClient) ListRepositories(ctx context.Context, org string, cursor *string) (*repositoryResponse, error) {
	ctx, span := c.tracer.Start(ctx, "github_graphql_client.list_repositories",
		trace.WithAttributes(
			attribute.String("controller_id", c.controllerID),
			attribute.String("org", org),
			attribute.String("cursor", stringOrNone(cursor)),
		))
	defer span.End()

	// GraphQL query to fetch repository names and pagination info.
	query := `
	query($org: String!, $after: String) {
			organization(login: $org) {
				repositories(first: 100, after: $after) {
					nodes {
						name
					}
					pageInfo {
						hasNextPage
						endCursor
					}
				}
			}
	}`

	variables := map[string]any{"org": org}
	if cursor != nil {
		variables["after"] = *cursor
	}

	resp, err := c.doRequest(ctx, query, variables)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to list repositories")
		return nil, fmt.Errorf("failed to list repositories for org %s: %w", org, err)
	}

	if resp != nil && resp.Data.Organization.Repositories.PageInfo.HasNextPage {
		span.SetAttributes(
			attribute.String("next_cursor", resp.Data.Organization.Repositories.PageInfo.EndCursor),
			attribute.Int("repos_count", len(resp.Data.Organization.Repositories.Nodes)),
		)
	}

	span.SetStatus(codes.Ok, "repositories listed successfully")
	return resp, nil
}

// doRequest executes a GraphQL request against GitHub's API.
func (c *GraphQLClient) doRequest(
	ctx context.Context,
	query string,
	variables map[string]any,
) (*repositoryResponse, error) {
	ctx, span := c.tracer.Start(ctx, "github_graphql_client.do_request",
		trace.WithAttributes(
			attribute.String("controller_id", c.controllerID),
		))
	defer span.End()

	const apiURL = "https://api.github.com/graphql"

	if err := c.rateLimiter.Wait(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "rate limiter wait failed")
		return nil, fmt.Errorf("rate limiter wait failed: %w", err)
	}

	bodyMap := map[string]any{
		"query":     query,
		"variables": variables,
	}
	bodyData, err := json.Marshal(bodyMap)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to marshal request")
		return nil, fmt.Errorf("failed to marshal GraphQL query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyData))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return nil, fmt.Errorf("failed to create GraphQL request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	span.SetAttributes(
		attribute.String("api_url", apiURL),
		attribute.Int("request_size", len(bodyData)),
	)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return nil, fmt.Errorf("GraphQL request failed: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("status_code", resp.StatusCode),
		attribute.String("status", resp.Status),
	)

	// Update rate limits based on response headers
	c.updateRateLimits(resp.Header)

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		span.RecordError(fmt.Errorf("non-200 response"))
		span.SetStatus(codes.Error, "non-200 response")
		return nil, fmt.Errorf("non-200 response from GitHub GraphQL API (status: %d): %s", resp.StatusCode, string(data))
	}

	var result repositoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to decode response")
		return nil, fmt.Errorf("failed to decode GraphQL response: %w", err)
	}

	if len(result.Errors) > 0 {
		span.RecordError(fmt.Errorf("GraphQL errors"))
		span.SetStatus(codes.Error, "GraphQL errors in response")
		return nil, fmt.Errorf("GraphQL response contained errors: %v", result.Errors)
	}

	span.SetStatus(codes.Ok, "request completed successfully")
	return &result, nil
}

// updateRateLimits updates the rate limiter based on GitHub's response headers
func (c *GraphQLClient) updateRateLimits(headers http.Header) {
	remaining := headers.Get("X-RateLimit-Remaining")
	reset := headers.Get("X-RateLimit-Reset")
	limit := headers.Get("X-RateLimit-Limit")

	remainingVal, _ := strconv.ParseInt(remaining, 10, 64)
	resetVal, _ := strconv.ParseInt(reset, 10, 64)
	limitVal, _ := strconv.ParseInt(limit, 10, 64)

	if remainingVal > 0 && resetVal > 0 && limitVal > 0 {
		resetTime := time.Unix(resetVal, 0)
		duration := time.Until(resetTime)
		if duration > 0 {
			// Calculate safe request rate to use remaining quota until reset.
			// Using 90% of the available rate to be conservative
			rps := float64(remainingVal) / duration.Seconds()
			c.rateLimiter.UpdateLimits(rps*0.9, int(remainingVal/10))
		}
	}
}

// Helper function to handle nil string pointers in attributes.
func stringOrNone(s *string) string {
	if s == nil {
		return "none"
	}
	return *s
}
