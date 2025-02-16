package scanning

import "github.com/ahrav/gitleaks-armada/internal/domain/shared"

// Target represents a scannable resource in the scanning domain.
type Target struct {
	name       string
	sourceType shared.SourceType
	auth       *Auth
	metadata   map[string]string // Common metadata moved to root level
	github     *GitHubTarget
	s3         *S3Target
	url        *URLTarget
}

// GitHubTarget contains GitHub-specific scanning configuration.
type GitHubTarget struct {
	org      string
	repoList []string
}

// S3Target contains S3-specific scanning configuration.
type S3Target struct {
	bucket string
	prefix string
	region string
}

// URLTarget contains URL-specific scanning configuration.
type URLTarget struct {
	urls []string
}

// NewTarget creates a new Target instance with type-specific configuration.
func NewTarget(
	name string,
	sourceType shared.SourceType,
	auth *Auth,
	metadata map[string]string,
	config TargetConfig,
) Target {
	return Target{
		name:       name,
		sourceType: sourceType,
		auth:       auth,
		metadata:   metadata,
		github:     config.GitHub,
		s3:         config.S3,
		url:        config.URL,
	}
}

// TargetConfig holds the type-specific configuration.
type TargetConfig struct {
	GitHub *GitHubTarget
	S3     *S3Target
	URL    *URLTarget
}

// Getters for Target
func (t Target) Name() string                  { return t.name }
func (t Target) SourceType() shared.SourceType { return t.sourceType }
func (t Target) Auth() *Auth                   { return t.auth }
func (t Target) Metadata() map[string]string   { return t.metadata }
func (t Target) GitHub() *GitHubTarget         { return t.github }
func (t Target) S3() *S3Target                 { return t.s3 }
func (t Target) URL() *URLTarget               { return t.url }
func (t Target) HasAuth() bool                 { return t.auth != nil }

// Constructors for specific target types
func NewGitHubTarget(org string, repoList []string) *GitHubTarget {
	return &GitHubTarget{
		org:      org,
		repoList: repoList,
	}
}

func NewS3Target(bucket, prefix, region string) *S3Target {
	return &S3Target{
		bucket: bucket,
		prefix: prefix,
		region: region,
	}
}

func NewURLTarget(urls []string) *URLTarget {
	return &URLTarget{
		urls: urls,
	}
}

// Getters for GitHubTarget
func (t *GitHubTarget) Org() string        { return t.org }
func (t *GitHubTarget) RepoList() []string { return t.repoList }

// Getters for S3Target
func (t *S3Target) Bucket() string { return t.bucket }
func (t *S3Target) Prefix() string { return t.prefix }
func (t *S3Target) Region() string { return t.region }

// Getters for URLTarget
func (t *URLTarget) URLs() []string { return t.urls }
