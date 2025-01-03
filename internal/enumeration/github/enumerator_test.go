package github

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
	"github.com/ahrav/gitleaks-armada/pkg/config"
	"github.com/ahrav/gitleaks-armada/pkg/domain"
	"github.com/ahrav/gitleaks-armada/pkg/domain/enumeration"
)

type MockGitHubAPI struct{ mock.Mock }

func (m *MockGitHubAPI) ListRepositories(ctx context.Context, org string, cursor *string) (*githubGraphQLResponse, error) {
	args := m.Called(ctx, org, cursor)
	if resp := args.Get(0); resp != nil {
		return resp.(*githubGraphQLResponse), args.Error(1)
	}
	return nil, args.Error(1)
}

type MockStorage struct{ mock.Mock }

func (m *MockStorage) Save(ctx context.Context, state *enumeration.EnumerationState) error {
	args := m.Called(ctx, state)
	return args.Error(0)
}

func (m *MockStorage) Load(ctx context.Context, sessionID string) (*enumeration.EnumerationState, error) {
	args := m.Called(ctx, sessionID)
	if state := args.Get(0); state != nil {
		return state.(*enumeration.EnumerationState), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStorage) GetActiveStates(ctx context.Context) ([]*enumeration.EnumerationState, error) {
	args := m.Called(ctx)
	if states := args.Get(0); states != nil {
		return states.([]*enumeration.EnumerationState), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStorage) List(ctx context.Context, limit int) ([]*enumeration.EnumerationState, error) {
	args := m.Called(ctx, limit)
	if states := args.Get(0); states != nil {
		return states.([]*enumeration.EnumerationState), args.Error(1)
	}
	return nil, args.Error(1)
}

func TestGitHubEnumerator_Enumerate(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func(*MockGitHubAPI, *MockStorage)
		state         *enumeration.EnumerationState
		expectedTasks int
	}{
		{
			name: "successful single page enumeration",
			setupMocks: func(api *MockGitHubAPI, store *MockStorage) {
				api.On("ListRepositories", mock.Anything, "test-org", (*string)(nil)).Return(&githubGraphQLResponse{
					Data: struct {
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
					}{
						Organization: struct {
							Repositories struct {
								Nodes []struct {
									Name string `json:"name"`
								} `json:"nodes"`
								PageInfo struct {
									HasNextPage bool   `json:"hasNextPage"`
									EndCursor   string `json:"endCursor"`
								} `json:"pageInfo"`
							} `json:"repositories"`
						}{
							Repositories: struct {
								Nodes []struct {
									Name string `json:"name"`
								} `json:"nodes"`
								PageInfo struct {
									HasNextPage bool   `json:"hasNextPage"`
									EndCursor   string `json:"endCursor"`
								} `json:"pageInfo"`
							}{
								Nodes: []struct {
									Name string `json:"name"`
								}{
									{Name: "repo1"},
									{Name: "repo2"},
								},
								PageInfo: struct {
									HasNextPage bool   `json:"hasNextPage"`
									EndCursor   string `json:"endCursor"`
								}{
									HasNextPage: false,
									EndCursor:   "",
								},
							},
						},
					},
				}, nil)
			},
			state: &enumeration.EnumerationState{
				SessionID:  "test-session",
				SourceType: "github",
				Status:     enumeration.StatusInProgress,
			},
			expectedTasks: 2,
		},
		{
			name: "successful multi-page enumeration",
			setupMocks: func(api *MockGitHubAPI, store *MockStorage) {
				// First page of results.
				api.On("ListRepositories", mock.Anything, "test-org", (*string)(nil)).Return(&githubGraphQLResponse{
					Data: struct {
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
					}{
						Organization: struct {
							Repositories struct {
								Nodes []struct {
									Name string `json:"name"`
								} `json:"nodes"`
								PageInfo struct {
									HasNextPage bool   `json:"hasNextPage"`
									EndCursor   string `json:"endCursor"`
								} `json:"pageInfo"`
							} `json:"repositories"`
						}{
							Repositories: struct {
								Nodes []struct {
									Name string `json:"name"`
								} `json:"nodes"`
								PageInfo struct {
									HasNextPage bool   `json:"hasNextPage"`
									EndCursor   string `json:"endCursor"`
								} `json:"pageInfo"`
							}{
								Nodes: []struct {
									Name string `json:"name"`
								}{
									{Name: "repo1"},
									{Name: "repo2"},
								},
								PageInfo: struct {
									HasNextPage bool   `json:"hasNextPage"`
									EndCursor   string `json:"endCursor"`
								}{
									HasNextPage: true,
									EndCursor:   "cursor1",
								},
							},
						},
					},
				}, nil)

				// Expect state save after first page.
				store.On("Save", mock.Anything, mock.MatchedBy(func(state *enumeration.EnumerationState) bool {
					return state.LastCheckpoint != nil &&
						state.LastCheckpoint.Data["endCursor"] == "cursor1"
				})).Return(nil)

				// Second page of results.
				api.On("ListRepositories", mock.Anything, "test-org", mock.MatchedBy(func(cursor *string) bool {
					return cursor != nil && *cursor == "cursor1"
				})).Return(&githubGraphQLResponse{
					Data: struct {
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
					}{
						Organization: struct {
							Repositories struct {
								Nodes []struct {
									Name string `json:"name"`
								} `json:"nodes"`
								PageInfo struct {
									HasNextPage bool   `json:"hasNextPage"`
									EndCursor   string `json:"endCursor"`
								} `json:"pageInfo"`
							} `json:"repositories"`
						}{
							Repositories: struct {
								Nodes []struct {
									Name string `json:"name"`
								} `json:"nodes"`
								PageInfo struct {
									HasNextPage bool   `json:"hasNextPage"`
									EndCursor   string `json:"endCursor"`
								} `json:"pageInfo"`
							}{
								Nodes: []struct {
									Name string `json:"name"`
								}{
									{Name: "repo3"},
									{Name: "repo4"},
								},
								PageInfo: struct {
									HasNextPage bool   `json:"hasNextPage"`
									EndCursor   string `json:"endCursor"`
								}{
									HasNextPage: false,
									EndCursor:   "",
								},
							},
						},
					},
				}, nil)
			},
			state: &enumeration.EnumerationState{
				SessionID:  "test-session",
				SourceType: "github",
				Status:     enumeration.StatusInProgress,
			},
			expectedTasks: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := &MockGitHubAPI{}
			mockStorage := &MockStorage{}
			tt.setupMocks(mockAPI, mockStorage)

			tracer, _, _ := otel.InitTracing(logger.NewWithHandler(slog.NewJSONHandler(io.Discard, nil)), otel.Config{})

			enumerator := NewGitHubEnumerator(
				mockAPI,
				&domain.TaskCredentials{
					Type: domain.CredentialTypeGitHub,
					Values: map[string]interface{}{
						"auth_token": "test-token",
					},
				},
				mockStorage,
				&config.GitHubTarget{Org: "test-org"},
				tracer.Tracer("test"),
			)

			taskCh := make(chan []domain.Task, 10)
			err := enumerator.Enumerate(context.Background(), tt.state, taskCh)

			assert.NoError(t, err)
			close(taskCh)

			var totalTasks int
			for tasks := range taskCh {
				totalTasks += len(tasks)
			}
			assert.Equal(t, tt.expectedTasks, totalTasks)

			mockAPI.AssertExpectations(t)
			mockStorage.AssertExpectations(t)
		})
	}
}

// TODO: Add tests for error cases.
