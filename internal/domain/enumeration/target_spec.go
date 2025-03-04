package enumeration

import (
	"encoding/json"
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// TODO: Revist all of this.
// TargetSpec is a value object that encapsulates the configuration for a scan target.
// It contains all necessary information to authenticate and enumerate resources.
type TargetSpec struct {
	name       string
	sourceType shared.SourceType
	auth       *AuthSpec
	github     *GitHubTargetSpec
	s3         *S3TargetSpec
	url        *URLTargetSpec
}

// GitHubTargetSpec defines parameters for scanning GitHub repositories.
type GitHubTargetSpec struct {
	Org      string
	RepoList []string
	Metadata map[string]string
}

// S3TargetSpec defines parameters for scanning S3 buckets.
type S3TargetSpec struct {
	Bucket   string
	Prefix   string
	Region   string
	Metadata map[string]string
}

// URLTargetSpec defines parameters for scanning URLs.
type URLTargetSpec struct {
	URLs          []string
	ArchiveFormat ArchiveFormat
	Headers       map[string]string
	RateLimit     float64
	RetryConfig   *RetryConfig
	Metadata      map[string]string
}

// RetryConfig defines retry behavior for URL requests.
type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
}

// ArchiveFormat represents supported archive/compression formats.
type ArchiveFormat string

const (
	ArchiveFormatNone   ArchiveFormat = "none"
	ArchiveFormatGzip   ArchiveFormat = "gzip"
	ArchiveFormatTarGz  ArchiveFormat = "tar.gz"
	ArchiveFormatZip    ArchiveFormat = "zip"
	ArchiveFormatWarcGz ArchiveFormat = "warc.gz"
	ArchiveFormatAuto   ArchiveFormat = "auto"
)

// NewTargetSpec creates a new target specification
func NewTargetSpec(
	name string,
	sourceType shared.SourceType,
	auth *AuthSpec,
) *TargetSpec {
	return &TargetSpec{
		name:       name,
		sourceType: sourceType,
		auth:       auth,
	}
}

// MarshalJSON implements json.Marshaler for TargetSpec.
func (t TargetSpec) MarshalJSON() ([]byte, error) {
	type targetJSON struct {
		Name       string            `json:"name"`
		SourceType string            `json:"source_type"`
		Auth       *AuthSpec         `json:"auth,omitempty"`
		GitHub     *GitHubTargetSpec `json:"github,omitempty"`
		S3         *S3TargetSpec     `json:"s3,omitempty"`
		URL        *URLTargetSpec    `json:"url,omitempty"`
	}

	return json.Marshal(targetJSON{
		Name:       t.name,
		SourceType: t.sourceType.String(),
		Auth:       t.auth,
		GitHub:     t.github,
		S3:         t.s3,
		URL:        t.url,
	})
}

// UnmarshalJSON implements json.Unmarshaler for TargetSpec.
func (t *TargetSpec) UnmarshalJSON(data []byte) error {
	var targetJSON struct {
		Name       string            `json:"name"`
		SourceType string            `json:"source_type"`
		Auth       *AuthSpec         `json:"auth,omitempty"`
		GitHub     *GitHubTargetSpec `json:"github,omitempty"`
		S3         *S3TargetSpec     `json:"s3,omitempty"`
		URL        *URLTargetSpec    `json:"url,omitempty"`
	}

	if err := json.Unmarshal(data, &targetJSON); err != nil {
		return err
	}

	t.name = targetJSON.Name
	t.sourceType = shared.ParseSourceType(targetJSON.SourceType)
	t.auth = targetJSON.Auth
	t.github = targetJSON.GitHub
	t.s3 = targetJSON.S3
	t.url = targetJSON.URL

	return nil
}

func (t *TargetSpec) Name() string { return t.name }

func (t *TargetSpec) SourceType() shared.SourceType { return t.sourceType }

func (t *TargetSpec) Auth() *AuthSpec { return t.auth }

func (t *TargetSpec) GitHub() *GitHubTargetSpec { return t.github }

func (t *TargetSpec) S3() *S3TargetSpec { return t.s3 }

func (t *TargetSpec) URL() *URLTargetSpec { return t.url }

func (t *TargetSpec) ArchiveFormat() ArchiveFormat { return t.url.ArchiveFormat }

func (t *TargetSpec) SetGitHub(github *GitHubTargetSpec) { t.github = github }

func (t *TargetSpec) SetS3(s3 *S3TargetSpec) { t.s3 = s3 }

func (t *TargetSpec) SetURL(url *URLTargetSpec) { t.url = url }
