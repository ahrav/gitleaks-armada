package orchestration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/ahrav/gitleaks-armada/pkg/config"
)

// Controller coordinates work distribution across a cluster of workers.
type Controller struct {
	coordinator Coordinator
	workQueue   Broker
	credStore   *CredentialStore

	mu            sync.Mutex
	running       bool
	cancelFn      context.CancelFunc
	currentTarget *config.TargetSpec

	httpClient *http.Client
}

// NewController creates a Controller instance that coordinates work distribution
// using the provided coordinator for leader election and broker for task queuing.
func NewController(coord Coordinator, queue Broker) *Controller {
	return &Controller{
		coordinator: coord,
		workQueue:   queue,
		httpClient:  new(http.Client),
	}
}

// Run starts the controller's leadership election process and target processing loop.
// Returns a channel that is closed when initialization is complete and any startup error.
func (o *Controller) Run(ctx context.Context) (<-chan struct{}, error) {
	ready := make(chan struct{})
	leaderCh := make(chan bool, 1)

	o.coordinator.OnLeadershipChange(func(isLeader bool) {
		log.Printf("Leadership change: isLeader=%v", isLeader)

		o.mu.Lock()
		o.running = isLeader
		if !isLeader && o.cancelFn != nil {
			o.cancelFn()
			o.cancelFn = nil
		}
		o.mu.Unlock()

		select {
		case leaderCh <- isLeader:
			log.Printf("Sent leadership status: %v", isLeader)
		default:
			log.Printf("Warning: leadership channel full, skipping update")
		}
	})

	go func() {
		readyClosed := false
		log.Println("Waiting for leadership signal...")

		for {
			select {
			case isLeader := <-leaderCh:
				if !isLeader {
					log.Println("Not leader, waiting...")
					continue
				}

				log.Println("Leadership acquired, processing targets...")
				if err := o.ProcessTarget(ctx); err != nil {
					log.Printf("Failed to process targets: %v", err)
				}

				if !readyClosed {
					close(ready)
					readyClosed = true
				}

			case <-ctx.Done():
				log.Println("Context cancelled, shutting down")
				if !readyClosed {
					close(ready)
				}
				return
			}
		}
	}()

	// Start the coordinator after after the leadership channel is ready.
	log.Println("Starting coordinator...")
	if err := o.coordinator.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start coordinator: %v", err)
	}

	return ready, nil
}

// Stop gracefully shuts down the orchestrator if it is running.
// Safe to call multiple times.
func (o *Controller) Stop() error {
	o.mu.Lock()
	if !o.running {
		o.mu.Unlock()
		return nil
	}
	o.running = false
	if o.cancelFn != nil {
		o.cancelFn()
	}
	o.mu.Unlock()

	log.Println("[Controller] Stopped.")
	return nil
}

// ProcessTarget reads the configuration file and creates scan tasks for each target.
func (o *Controller) ProcessTarget(ctx context.Context) error {
	const configPath = "/etc/scanner/config/config.yaml"

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	credStore, err := NewCredentialStore(cfg.Auth)
	if err != nil {
		return fmt.Errorf("failed to initialize credential store: %w", err)
	}
	o.credStore = credStore
	log.Println("Credential store initialized successfully.")

	for _, target := range cfg.Targets {
		creds, err := o.credStore.GetCredentials(target.AuthRef)
		if err != nil {
			return fmt.Errorf("failed to get credentials for target: %w", err)
		}

		switch target.SourceType {
		case config.SourceTypeGitHub:
			if target.GitHub == nil {
				return fmt.Errorf("github target configuration is missing")
			}

			var token string
			if creds.Type == CredentialTypeGitHub {
				token, err = extractGitHubToken(creds)
				if err != nil {
					return fmt.Errorf("failed to extract GitHub token: %w", err)
				}
			}

			if err := o.processGitHubTarget(ctx, token, target.GitHub, creds); err != nil {
				return fmt.Errorf("failed to process github target: %w", err)
			}
		}
	}
	return nil
}

// processGitHubTarget handles scanning tasks for GitHub repositories, either from an organization
// or individual repo list. It publishes tasks in batches to match GitHub's API pagination.
func (o *Controller) processGitHubTarget(
	ctx context.Context,
	token string,
	ghConfig *config.GitHubTarget,
	creds *TaskCredentials,
) error {
	taskCh := make(chan []Task)
	errCh := make(chan error, 1)

	// Start publisher goroutine to handle batches of tasks.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for tasks := range taskCh {
			if err := o.workQueue.PublishTasks(ctx, tasks); err != nil {
				errCh <- fmt.Errorf("failed to publish tasks: %w", err)
				return
			}
			log.Printf("Published batch of %d tasks", len(tasks))
		}
	}()

	if ghConfig.Org != "" {
		if err := o.processGitHubOrgRepos(ctx, token, ghConfig.Org, ghConfig.Metadata, creds, taskCh); err != nil {
			close(taskCh)
			return fmt.Errorf("failed to process github org repos: %w", err)
		}
	}

	if len(ghConfig.RepoList) > 0 {
		tasks := make([]Task, 0, len(ghConfig.RepoList))
		for _, repo := range ghConfig.RepoList {
			tasks = append(tasks, Task{
				TaskID:      generateTaskID(),
				ResourceURI: buildGithubResourceURI(ghConfig.Org, repo),
				Metadata:    ghConfig.Metadata,
				Credentials: creds,
			})
		}
		taskCh <- tasks
	}

	close(taskCh)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// processGitHubOrgRepos fetches all repositories for a GitHub organization using GraphQL pagination
// and creates scan tasks for each repository.
func (o *Controller) processGitHubOrgRepos(
	ctx context.Context,
	token string,
	org string,
	metadata map[string]string,
	creds *TaskCredentials,
	taskCh chan<- []Task,
) error {
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

	var endCursor *string
	const batchSize = 100 // Max repos per GraphQL query

	for {
		variables := map[string]any{
			"org": org,
		}
		if endCursor != nil {
			variables["after"] = *endCursor
		}

		respData, err := doGitHubGraphQLRequest(ctx, o.httpClient, token, query, variables)
		if err != nil {
			return err
		}

		tasks := make([]Task, 0, batchSize)
		for _, node := range respData.Data.Organization.Repositories.Nodes {
			tasks = append(tasks, Task{
				TaskID:      generateTaskID(),
				ResourceURI: buildGithubResourceURI(org, node.Name),
				Metadata:    metadata,
				Credentials: creds,
			})
		}

		if len(tasks) > 0 {
			taskCh <- tasks
		}

		pageInfo := respData.Data.Organization.Repositories.PageInfo
		if !pageInfo.HasNextPage {
			break
		}
		endCursor = &pageInfo.EndCursor
	}

	return nil
}

// extractGitHubToken retrieves the authentication token from GitHub credentials.
// Returns an error if credentials are invalid or token is missing.
func extractGitHubToken(creds *TaskCredentials) (string, error) {
	if creds.Type != CredentialTypeGitHub && creds.Type != CredentialTypeUnauthenticated {
		return "", fmt.Errorf("expected github credentials, got %s", creds.Type)
	}

	tokenVal, ok := creds.Values["auth_token"].(string)
	if !ok || tokenVal == "" {
		return "", fmt.Errorf("auth_token missing or empty in GitHub credentials")
	}
	return tokenVal, nil
}

// githubGraphQLResponse represents the structure of GitHub's GraphQL API response
// for repository queries.
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

// doGitHubGraphQLRequest executes a GraphQL query against GitHub's API with proper authentication
// and error handling.
func doGitHubGraphQLRequest(
	ctx context.Context,
	client *http.Client,
	token string,
	query string,
	variables map[string]any,
) (*githubGraphQLResponse, error) {
	const apiUrl = "https://api.github.com/graphql"

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

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graphql request failed: %w", err)
	}
	defer resp.Body.Close()

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

// generateTaskID creates a unique identifier for each scan task.
func generateTaskID() string { return uuid.New().String() }

// buildGithubResourceURI creates a standardized URI for scan targets in the format "https://github.com/org/repo.git".
func buildGithubResourceURI(org, repoName string) string {
	return fmt.Sprintf("https://github.com/%s/%s.git", org, repoName)
}
