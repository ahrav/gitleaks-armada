package enumeration

import (
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// TODO: Revist all of this.
// TargetSpec is a value object that encapsulates the configuration for a scan target.
// It contains all necessary information to authenticate and enumerate resources.
type TargetSpec struct {
	name       string
	sourceType shared.SourceType
	authRef    string
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
	authRef string,
	auth *AuthSpec,
	// github *GitHubTargetSpec,
	// s3 *S3TargetSpec,
	// url *URLTargetSpec,
) *TargetSpec {
	return &TargetSpec{
		name:       name,
		sourceType: sourceType,
		authRef:    authRef,
		auth:       auth,
		// github:     github,
		// s3:         s3,
		// url:        url,
	}
}

func (t *TargetSpec) Name() string { return t.name }

func (t *TargetSpec) SourceType() shared.SourceType { return t.sourceType }

func (t *TargetSpec) AuthRef() string { return t.authRef }

func (t *TargetSpec) Auth() *AuthSpec { return t.auth }

func (t *TargetSpec) GitHub() *GitHubTargetSpec { return t.github }

func (t *TargetSpec) S3() *S3TargetSpec { return t.s3 }

func (t *TargetSpec) URL() *URLTargetSpec { return t.url }

func (t *TargetSpec) ArchiveFormat() ArchiveFormat { return t.url.ArchiveFormat }

func (t *TargetSpec) SetGitHub(github *GitHubTargetSpec) { t.github = github }

func (t *TargetSpec) SetS3(s3 *S3TargetSpec) { t.s3 = s3 }

func (t *TargetSpec) SetURL(url *URLTargetSpec) { t.url = url }
