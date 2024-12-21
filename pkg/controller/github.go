package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common"
	"github.com/ahrav/gitleaks-armada/pkg/config"
	"github.com/ahrav/gitleaks-armada/pkg/messaging"
)

// GitHubEnumerator handles enumerating repositories from a GitHub organization.
// It supports pagination and checkpoint-based resumption to handle large organizations
// efficiently and reliably.
type GitHubEnumerator struct {
	ghConfig *config.GitHubTarget
	creds    *messaging.TaskCredentials
	token    string

	ghClient *GitHubClient
	storage  EnumerationStateStorage
}

// NewGitHubEnumerator creates a new GitHubEnumerator with the provided HTTP client,
// credentials and state storage. It validates and extracts the GitHub authentication
// token if GitHub credentials are provided.
func NewGitHubEnumerator(
	httpClient *http.Client,
	creds *messaging.TaskCredentials,
	storage EnumerationStateStorage,
) (*GitHubEnumerator, error) {
	var token string
	if creds.Type == messaging.CredentialTypeGitHub {
		var err error
		token, err = extractGitHubToken(creds)
		if err != nil {
			return nil, fmt.Errorf("failed to extract GitHub token: %w", err)
		}
	}
	return &GitHubEnumerator{
		ghClient: NewGitHubClient(httpClient),
		token:    token,
		creds:    creds,
		storage:  storage,
	}, nil
}

// extractGitHubToken retrieves and validates the authentication token from GitHub credentials.
// It returns an error if the credentials are not GitHub type or if the token is missing.
func extractGitHubToken(creds *messaging.TaskCredentials) (string, error) {
	if creds.Type != messaging.CredentialTypeGitHub && creds.Type != messaging.CredentialTypeUnauthenticated {
		return "", fmt.Errorf("expected github credentials, got %s", creds.Type)
	}

	tokenVal, ok := creds.Values["auth_token"].(string)
	if !ok || tokenVal == "" {
		return "", fmt.Errorf("auth_token missing or empty in GitHub credentials")
	}
	return tokenVal, nil
}

// Enumerate fetches all repositories from a GitHub organization and creates scan tasks.
// It uses GraphQL for efficient pagination and maintains checkpoints for resumability.
// The method streams batches of tasks through the provided channel and updates progress
// in the enumeration state storage.
func (e *GitHubEnumerator) Enumerate(ctx context.Context, checkpoint *Checkpoint, taskCh chan<- []messaging.Task) error {
	if e.ghConfig.Org == "" {
		return fmt.Errorf("must provide a valid org")
	}

	// Load state to track progress.
	state, err := e.storage.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to load enumeration state: %w", err)
	}
	if state == nil {
		return fmt.Errorf("enumeration state is nil")
	}

	// Resume from last known position if checkpoint exists.
	var endCursor *string
	if checkpoint != nil {
		cursor, ok := checkpoint.Data["endCursor"].(string)
		if ok {
			endCursor = &cursor
		}
	}

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

	const batchSize = 100 // GitHub GraphQL API limit per query
	for {
		variables := map[string]any{
			"org": e.ghConfig.Org,
		}
		if endCursor != nil {
			variables["after"] = *endCursor
		}

		respData, err := e.ghClient.doGitHubGraphQLRequest(ctx, e.token, query, variables)
		if err != nil {
			return err
		}

		tasks := make([]messaging.Task, 0, batchSize)
		for _, node := range respData.Data.Organization.Repositories.Nodes {
			tasks = append(tasks, messaging.Task{
				TaskID:      generateTaskID(),
				ResourceURI: buildGithubResourceURI(e.ghConfig.Org, node.Name),
				Metadata:    e.ghConfig.Metadata,
				Credentials: e.creds,
			})
		}

		if len(tasks) > 0 {
			taskCh <- tasks
		}

		pageInfo := respData.Data.Organization.Repositories.PageInfo
		if !pageInfo.HasNextPage {
			break
		}

		// Save progress after each successful batch.
		// I think this is granular enough to resume from.
		endCursor = &pageInfo.EndCursor
		checkpoint = &Checkpoint{
			TargetID: e.ghConfig.Org,
			Data: map[string]any{
				"endCursor": *endCursor,
			},
			UpdatedAt: time.Now(),
		}
		state.LastCheckpoint = checkpoint
		state.LastUpdated = time.Now()
		if err := e.storage.Save(ctx, state); err != nil {
			return fmt.Errorf("failed to save enumeration state with new checkpoint: %w", err)
		}
		log.Printf("Checkpoint updated: endCursor=%s", *endCursor)
	}

	return nil
}

// githubGraphQLResponse represents the structure of GitHub's GraphQL API response
// for repository queries.
// It includes both the repository data and any potential error messages.
type githubGraphQLResponse struct {
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

// buildGithubResourceURI creates a standardized URI for GitHub repositories.
// The URI format follows the standard HTTPS clone URL pattern used by GitHub.
func buildGithubResourceURI(org, repoName string) string {
	return fmt.Sprintf("https://github.com/%s/%s.git", org, repoName)
}

type GitHubClient struct {
	httpClient  *http.Client
	rateLimiter *common.RateLimiter
}

// NewGitHubClient creates a new GitHub client with rate limiting.
func NewGitHubClient(httpClient *http.Client) *GitHubClient {
	// GitHub's default rate limit is 5000 requests per hour.
	// Setting initial rate to 4500/hour (1.25/second) to be conservative.
	// TODO: Figure out a way to pool tokens?
	return &GitHubClient{
		httpClient:  httpClient,
		rateLimiter: common.NewRateLimiter(1.25, 5),
	}
}

// doGitHubGraphQLRequest executes a GraphQL query against GitHub's API with rate limiting.
// It handles authentication, request formatting, and response parsing while respecting
// GitHub's API rate limits. The method automatically updates rate limiting parameters
// based on GitHub's response headers.
func (c *GitHubClient) doGitHubGraphQLRequest(
	ctx context.Context,
	token string,
	query string,
	variables map[string]any,
) (*githubGraphQLResponse, error) {
	const apiUrl = "https://api.github.com/graphql"

	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter wait failed: %w", err)
	}

	bodyMap := map[string]any{
		"query":     query,
		"variables": variables,
	}
	bodyData, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal graphql query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiUrl, bytes.NewReader(bodyData))
	if err != nil {
		return nil, fmt.Errorf("failed to create graphql request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graphql request failed: %w", err)
	}
	defer resp.Body.Close()

	// Dynamically adjust rate limits based on GitHub's response
	c.updateRateLimits(resp.Header)

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("non-200 response from GitHub GraphQL API: %d %s", resp.StatusCode, string(data))
	}

	var result githubGraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode graphql response: %w", err)
	}

	if len(result.Errors) > 0 {
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
func (c *GitHubClient) updateRateLimits(headers http.Header) {
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
