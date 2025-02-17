package config

import (
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// TODO: Think through a couple approaches for handling credentials.
// 1. Provide integration with a secrets manager. (AWS Secret Manager, Vault, etc.)
// 2. Credential Forwarding using a SDK to encrypt client creds with server-side public key.
// This would require a separate API endpoint.
// 3. Oauth2.0 flow for some sources.
// 4. Encrypted credential storage with strong key management.
// AuthConfig represents an authentication configuration.
type AuthConfig struct {
	Type        string         `yaml:"type" json:"type"`
	Credentials map[string]any `yaml:"credentials" json:"credentials"`
}

// Config represents the top-level configuration.
type Config struct {
	Auth    map[string]AuthConfig `yaml:"auth" json:"auth"`
	Targets []TargetSpec          `yaml:"targets" json:"targets"`
	API     APIConfig             `yaml:"api" json:"api"`
}

// APIConfig holds configuration for the API server.
type APIConfig struct {
	Host string `yaml:"host" json:"host" env:"API_HOST" envDefault:"0.0.0.0"`
	Port string `yaml:"port" json:"port" env:"API_PORT" envDefault:"8080"`
}

// TargetSpec is a generic wrapper for different source types.
type TargetSpec struct {
	Name       string            `yaml:"name" json:"name"`
	SourceType shared.SourceType `yaml:"source_type" json:"source_type"`
	SourceAuth *AuthConfig       `yaml:"source_auth,omitempty" json:"source_auth,omitempty"`
	Metadata   map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
	GitHub     *GitHubTarget     `yaml:"github,omitempty" json:"github,omitempty"`
	S3         *S3Target         `yaml:"s3,omitempty" json:"s3,omitempty"`
	URL        *URLTarget        `yaml:"url,omitempty" json:"url,omitempty"`
}

// GitHubTarget defines parameters for scanning GitHub repositories.
type GitHubTarget struct {
	Org      string   `yaml:"org,omitempty" json:"org,omitempty"`
	RepoList []string `yaml:"repo_list,omitempty" json:"repo_list,omitempty"`
}

// S3Target defines parameters for scanning S3 buckets.
type S3Target struct {
	Bucket string `yaml:"bucket" json:"bucket"`
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Region string `yaml:"region,omitempty" json:"region,omitempty"`
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
	URLs []string `yaml:"urls" json:"urls"`

	// ArchiveFormat specifies how the data is compressed/archived.
	// This can be "none", "gzip", "tar.gz", "zip", "warc.gz", or "auto".
	ArchiveFormat ArchiveFormat `yaml:"archive_format,omitempty" json:"archive_format,omitempty"`

	// Headers allows setting custom HTTP headers for the request(s).
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// RateLimit is the maximum number of requests per second for these URLs.
	// Zero (or omitted) means no rate limiting.
	RateLimit float64 `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`

	// RetryConfig defines how the client should attempt retries on failures.
	RetryConfig *RetryConfig `yaml:"retry,omitempty" json:"retry,omitempty"`
}

// RetryConfig defines basic retry behavior for URL requests.
type RetryConfig struct {
	// MaxAttempts is how many times to retry before giving up.
	MaxAttempts int `yaml:"max_attempts,omitempty" json:"max_attempts,omitempty"`

	// InitialWait is the initial backoff duration (e.g., 1s).
	InitialWait time.Duration `yaml:"initial_wait,omitempty" json:"initial_wait,omitempty"`

	// MaxWait is the upper bound for the backoff (e.g., 30s).
	MaxWait time.Duration `yaml:"max_wait,omitempty" json:"max_wait,omitempty"`
}
