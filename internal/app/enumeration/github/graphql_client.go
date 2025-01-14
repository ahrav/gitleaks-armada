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
	"go.opentelemetry.io/otel/trace"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/pkg/common"
)

// GraphQLClient is a wrapper around the GitHub GraphQL API client with rate limiting and tracing.
type GraphQLClient struct {
	httpClient  *http.Client
	token       string
	rateLimiter *common.RateLimiter

	tracer trace.Tracer
}

// NewGraphQLClient creates a new GraphQL client with rate limiting.
func NewGraphQLClient(
	httpClient *http.Client,
	creds *domain.TaskCredentials,
	tracer trace.Tracer,
) (*GraphQLClient, error) {
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
	// TODO: Figure out a way to pool tokens?
	return &GraphQLClient{
		httpClient:  httpClient,
		rateLimiter: common.NewRateLimiter(1.25, 5),
		token:       token,
		tracer:      tracer,
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
	ctx, span := c.tracer.Start(ctx, "github_enumerator.enumeration.list_repositories",
		trace.WithAttributes(
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
		return nil, err
	}

	if resp != nil && resp.Data.Organization.Repositories.PageInfo.HasNextPage {
		span.SetAttributes(
			attribute.String("next_cursor", resp.Data.Organization.Repositories.PageInfo.EndCursor),
			attribute.Int("repos_count", len(resp.Data.Organization.Repositories.Nodes)),
		)
	}

	return resp, nil
}

// doRequest executes a request against GitHub's API.
func (c *GraphQLClient) doRequest(
	ctx context.Context,
	query string,
	variables map[string]any,
) (*repositoryResponse, error) {
	ctx, span := c.tracer.Start(ctx, "github_enumerator.do_github_graphql_request")
	defer span.End()

	const apiUrl = "https://api.github.com/graphql"

	if err := c.rateLimiter.Wait(ctx); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("rate limiter wait failed: %w", err)
	}

	bodyMap := map[string]any{
		"query":     query,
		"variables": variables,
	}
	bodyData, err := json.Marshal(bodyMap)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to marshal graphql query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiUrl, bytes.NewReader(bodyData))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create graphql request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	span.SetAttributes(
		attribute.String("api_url", apiUrl),
		attribute.Int("request_size", len(bodyData)),
	)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("graphql request failed: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("status_code", resp.StatusCode),
		attribute.String("status", resp.Status),
	)

	// Dynamically adjust rate limits based on GitHub's response.
	c.updateRateLimits(resp.Header)

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		span.RecordError(fmt.Errorf("non-200 response: %s", string(data)))
		return nil, fmt.Errorf("non-200 response from GitHub GraphQL API: %d %s", resp.StatusCode, string(data))
	}

	var result repositoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decode graphql response: %w", err)
	}

	if len(result.Errors) > 0 {
		span.RecordError(fmt.Errorf("graphql errors: %v", result.Errors))
		return nil, fmt.Errorf("graphql errors: %v", result.Errors)
	}

	return &result, nil
}

// updateRateLimits adjusts the rate limiter settings based on GitHub's rate limit headers.
// It calculates a conservative request rate (90% of available) to prevent hitting limits
// while maximizing throughput. The method uses X-RateLimit headers to determine:
// - Remaining requests in the current window
// - When the rate limit window resets
// - Total requests allowed per window
//
// TODO: Review this again...
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
