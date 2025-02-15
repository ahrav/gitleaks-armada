package enumeration

import (
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// TargetSpec is a value object that encapsulates the configuration for a scan target.
// It contains all necessary information to authenticate and enumerate resources.
type TargetSpec struct {
	Name       string
	SourceType shared.SourceType
	AuthRef    string
	GitHub     *GitHubTargetSpec
	S3         *S3TargetSpec
	URL        *URLTargetSpec
}

// GitHubTargetSpec defines parameters for scanning GitHub repositories
type GitHubTargetSpec struct {
	Org      string
	RepoList []string
	Metadata map[string]string
}

// S3TargetSpec defines parameters for scanning S3 buckets
type S3TargetSpec struct {
	Bucket   string
	Prefix   string
	Region   string
	Metadata map[string]string
}

// URLTargetSpec defines parameters for scanning URLs
type URLTargetSpec struct {
	URLs          []string
	ArchiveFormat ArchiveFormat
	Headers       map[string]string
	RateLimit     float64
	RetryConfig   *RetryConfig
	Metadata      map[string]string
}

// RetryConfig defines retry behavior for URL requests
type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
}

// ArchiveFormat represents supported archive/compression formats
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
	github *GitHubTargetSpec,
	s3 *S3TargetSpec,
	url *URLTargetSpec,
) *TargetSpec {
	return &TargetSpec{
		Name:       name,
		SourceType: sourceType,
		AuthRef:    authRef,
		GitHub:     github,
		S3:         s3,
		URL:        url,
	}
}

// FromConfig creates a TargetSpec from a configuration TargetSpec
// func FromConfig(cfg *config.TargetSpec) *TargetSpec {
// 	spec := &TargetSpec{
// 		Name:       cfg.Name,
// 		SourceType: shared.SourceType(cfg.SourceType),
// 		AuthRef:    cfg.AuthRef,
// 	}

// 	if cfg.GitHub != nil {
// 		spec.GitHub = &GitHubTargetSpec{
// 			Org:      cfg.GitHub.Org,
// 			RepoList: cfg.GitHub.RepoList,
// 			Metadata: cfg.GitHub.Metadata,
// 		}
// 	}

// 	if cfg.S3 != nil {
// 		spec.S3 = &S3TargetSpec{
// 			Bucket:   cfg.S3.Bucket,
// 			Prefix:   cfg.S3.Prefix,
// 			Region:   cfg.S3.Region,
// 			Metadata: cfg.S3.Metadata,
// 		}
// 	}

// 	if cfg.URL != nil {
// 		spec.URL = &URLTargetSpec{
// 			URLs:          cfg.URL.URLs,
// 			ArchiveFormat: ArchiveFormat(cfg.URL.ArchiveFormat),
// 			Headers:       cfg.URL.Headers,
// 			RateLimit:     cfg.URL.RateLimit,
// 			Metadata:      cfg.URL.Metadata,
// 		}
// 		if cfg.URL.RetryConfig != nil {
// 			spec.URL.RetryConfig = &RetryConfig{
// 				MaxAttempts: cfg.URL.RetryConfig.MaxAttempts,
// 				InitialWait: cfg.URL.RetryConfig.InitialWait,
// 				MaxWait:     cfg.URL.RetryConfig.MaxWait,
// 			}
// 		}
// 	}

// 	return spec
// }
