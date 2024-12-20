package config

// SourceType enumerates the supported source types.
type SourceType string

const (
	SourceTypeGitHub SourceType = "github"
	SourceTypeS3     SourceType = "s3"
	// Add more as needed....
)

// AuthConfig represents an authentication configuration
type AuthConfig struct {
	Type   string         `yaml:"type"`
	Config map[string]any `yaml:"config"`
}

// Config represents the top-level configuration
type Config struct {
	Auth    map[string]AuthConfig `yaml:"auth"`
	Targets []TargetSpec          `yaml:"targets"`
}

// TargetSpec is a generic wrapper for different source types
type TargetSpec struct {
	SourceType SourceType     `yaml:"source_type"`
	AuthRef    string         `yaml:"auth_ref"`
	GitHub     *GitHubTarget  `yaml:"github,omitempty"`
	S3         *S3Target      `yaml:"s3,omitempty"`
}

// GitHubTarget defines parameters for scanning GitHub repositories
type GitHubTarget struct {
	Org      string            `yaml:"org,omitempty"`
	RepoList []string          `yaml:"repo_list,omitempty"`
	Metadata map[string]string `yaml:"metadata,omitempty"`
}

// S3Target defines parameters for scanning S3 buckets
type S3Target struct {
	Bucket   string            `yaml:"bucket"`
	Prefix   string            `yaml:"prefix,omitempty"`
	Region   string            `yaml:"region,omitempty"`
	Metadata map[string]string `yaml:"metadata,omitempty"`
}
