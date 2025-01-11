package scanning

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewGitHubRepo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input struct {
			name     string
			url      string
			metadata map[string]any
		}
		wantErr bool
	}{
		{
			name: "valid GitHub repository",
			input: struct {
				name     string
				url      string
				metadata map[string]any
			}{
				name:     "test-repo",
				url:      "https://github.com/test-owner/test-repo",
				metadata: map[string]any{"key": "value"},
			},
			wantErr: false,
		},
		{
			name: "empty name",
			input: struct {
				name     string
				url      string
				metadata map[string]any
			}{
				name:     "",
				url:      "https://github.com/test-owner/test-repo",
				metadata: nil,
			},
			wantErr: true,
		},
		{
			name: "empty url",
			input: struct {
				name     string
				url      string
				metadata map[string]any
			}{
				name:     "test-repo",
				url:      "",
				metadata: nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, err := NewGitHubRepo(tt.input.name, tt.input.url, tt.input.metadata)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, repo)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, repo)
			assert.Equal(t, tt.input.name, repo.Name())
			assert.Equal(t, tt.input.url, repo.URL())
			assert.Equal(t, tt.input.metadata, repo.Metadata())
			assert.True(t, repo.IsActive())
			assert.NotZero(t, repo.CreatedAt())
			assert.NotZero(t, repo.UpdatedAt())
		})
	}
}

func TestReconstructGitHubRepo(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	timeProvider := &mockTimeProvider{currentTime: fixedTime}
	timeline := NewTimeline(timeProvider)

	metadata := map[string]any{"key": "value"}

	repo := ReconstructGitHubRepo(
		123,
		"test-repo",
		"https://github.com/test-owner/test-repo",
		true,
		metadata,
		timeline,
	)

	assert.NotNil(t, repo)
	assert.Equal(t, int64(123), repo.ID())
	assert.Equal(t, "test-repo", repo.Name())
	assert.Equal(t, "https://github.com/test-owner/test-repo", repo.URL())
	assert.True(t, repo.IsActive())
	assert.Equal(t, metadata, repo.Metadata())
	assert.Equal(t, fixedTime, repo.CreatedAt())
	assert.Equal(t, fixedTime, repo.UpdatedAt())
}

func TestGitHubRepo_Deactivate(t *testing.T) {
	t.Parallel()

	repo, err := NewGitHubRepo("test-repo", "https://github.com/test-owner/test-repo", nil)
	assert.NoError(t, err)

	assert.True(t, repo.IsActive())
	repo.Deactivate()
	assert.False(t, repo.IsActive())
	assert.NotZero(t, repo.UpdatedAt())
}

func TestGitHubRepo_Rename(t *testing.T) {
	t.Parallel()

	repo, err := NewGitHubRepo("test-repo", "https://github.com/test-owner/test-repo", nil)
	assert.NoError(t, err)

	originalUpdatedAt := repo.UpdatedAt()
	err = repo.Rename("new-repo-name")
	assert.NoError(t, err)
	assert.Equal(t, "new-repo-name", repo.Name())
	assert.True(t, repo.UpdatedAt().After(originalUpdatedAt))

	err = repo.Rename("")
	assert.Error(t, err)
}
