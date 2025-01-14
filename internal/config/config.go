package config

import "time"

// SourceType enumerates the supported source types.
type SourceType string

const (
	SourceTypeGitHub SourceType = "github"
	SourceTypeS3     SourceType = "s3"
	SourceTypeURL    SourceType = "url"
	// Add more as needed....
)

// AuthConfig represents an authentication configuration.
type AuthConfig struct {
	Type   string         `yaml:"type"`
	Config map[string]any `yaml:"config"`
}

// Config represents the top-level configuration.
type Config struct {
	Auth    map[string]AuthConfig `yaml:"auth"`
	Targets []TargetSpec          `yaml:"targets"`
}

// TargetSpec is a generic wrapper for different source types.
type TargetSpec struct {
	Name       string        `yaml:"name"`
	SourceType SourceType    `yaml:"source_type"`
	AuthRef    string        `yaml:"auth_ref"`
	GitHub     *GitHubTarget `yaml:"github,omitempty"`
	S3         *S3Target     `yaml:"s3,omitempty"`
	URL        *URLTarget    `yaml:"url,omitempty"`
}

// GitHubTarget defines parameters for scanning GitHub repositories.
type GitHubTarget struct {
	Org      string            `yaml:"org,omitempty"`
	RepoList []string          `yaml:"repo_list,omitempty"`
	Metadata map[string]string `yaml:"metadata,omitempty"`
}

// S3Target defines parameters for scanning S3 buckets.
type S3Target struct {
	Bucket   string            `yaml:"bucket"`
	Prefix   string            `yaml:"prefix,omitempty"`
	Region   string            `yaml:"region,omitempty"`
	Metadata map[string]string `yaml:"metadata,omitempty"`
}

// ArchiveFormat enumerates supported archive/compression formats.
type ArchiveFormat string

const (
	ArchiveFormatNone   ArchiveFormat = "none"    // raw data
	ArchiveFormatGzip   ArchiveFormat = "gzip"    // single gzip-compressed file
	ArchiveFormatTarGz  ArchiveFormat = "tar.gz"  // tar archive, gzip-compressed
	ArchiveFormatZip    ArchiveFormat = "zip"     // zip archive
	ArchiveFormatWarcGz ArchiveFormat = "warc.gz" // WARC file compressed with gzip
	ArchiveFormatAuto   ArchiveFormat = "auto"    // auto-detect
)

// URLTarget defines parameters for scanning data from one or more URLs.
type URLTarget struct {
	// URLs can be a single URL or a list of URLs to scan.
	URLs []string `yaml:"urls"`

	// ArchiveFormat specifies how the data is compressed/archived.
	// This can be "none", "gzip", "tar.gz", "zip", "warc.gz", or "auto".
	ArchiveFormat ArchiveFormat `yaml:"archive_format,omitempty"`

	// Headers allows setting custom HTTP headers for the request(s).
	Headers map[string]string `yaml:"headers,omitempty"`

	// RateLimit is the maximum number of requests per second for these URLs.
	// Zero (or omitted) means no rate limiting.
	RateLimit float64 `yaml:"rate_limit,omitempty"`

	// RetryConfig defines how the client should attempt retries on failures.
	RetryConfig *RetryConfig `yaml:"retry,omitempty"`

	// Metadata can be used to store arbitrary key/value data for labeling or
	// grouping scan results.
	Metadata map[string]string `yaml:"metadata,omitempty"`
}

// RetryConfig defines basic retry behavior for URL requests.
type RetryConfig struct {
	// MaxAttempts is how many times to retry before giving up.
	MaxAttempts int `yaml:"max_attempts,omitempty"`

	// InitialWait is the initial backoff duration (e.g., 1s).
	InitialWait time.Duration `yaml:"initial_wait,omitempty"`

	// MaxWait is the upper bound for the backoff (e.g., 30s).
	MaxWait time.Duration `yaml:"max_wait,omitempty"`
}
