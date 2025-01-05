package shared

// SourceType identifies the type of source system that contains resources to be scanned.
// This allows the scanner to properly handle authentication and access patterns for
// different source control and storage systems.
type SourceType string

const (
	// SourceTypeGitHub represents GitHub repositories as a source system.
	// Tasks with this source type will use GitHub-specific authentication and API access.
	SourceTypeGitHub SourceType = "github"

	// SourceTypeS3 represents Amazon S3 buckets as a source system.
	// Tasks with this source type will use AWS credentials and S3-specific access patterns.
	SourceTypeS3 SourceType = "s3"
)
