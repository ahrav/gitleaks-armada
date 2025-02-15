package shared

// SourceType identifies the type of source system that contains resources to be scanned.
// This allows the scanner to properly handle authentication and access patterns for
// different source control and storage systems.
type SourceType int32

const (
	// SourceTypeUnspecified represents an unspecified or invalid source type.
	SourceTypeUnspecified SourceType = 0

	// SourceTypeGitHub represents GitHub repositories as a source system.
	// Tasks with this source type will use GitHub-specific authentication and API access.
	SourceTypeGitHub SourceType = 1

	// SourceTypeS3 represents Amazon S3 buckets as a source system.
	// Tasks with this source type will use AWS credentials and S3-specific access patterns.
	SourceTypeS3 SourceType = 2

	// SourceTypeURL represents a list of URLs as a source system.
	// Tasks with this source type will use URL-specific authentication and API access.
	SourceTypeURL SourceType = 3
)

// String returns the string representation of the SourceType in lowercase.
// This maintains compatibility with existing code that expects "github", "s3", "url"
func (s SourceType) String() string {
	switch s {
	case SourceTypeGitHub:
		return "github"
	case SourceTypeS3:
		return "s3"
	case SourceTypeURL:
		return "url"
	default:
		return "unspecified"
	}
}

// ProtoString returns the SCREAMING_SNAKE_CASE string representation
// of the SourceType. Used for protobuf enum string values.
func (s SourceType) ProtoString() string {
	switch s {
	case SourceTypeGitHub:
		return "SOURCE_TYPE_GITHUB"
	case SourceTypeS3:
		return "SOURCE_TYPE_S3"
	case SourceTypeURL:
		return "SOURCE_TYPE_URL"
	default:
		return "SOURCE_TYPE_UNSPECIFIED"
	}
}

// Int32 returns the int32 value for protobuf enum values.
func (s SourceType) Int32() int32 { return int32(s) }

// ParseSourceType converts a string to a SourceType.
func ParseSourceType(s string) SourceType {
	switch s {
	case "github", "SOURCE_TYPE_GITHUB":
		return SourceTypeGitHub
	case "s3", "SOURCE_TYPE_S3":
		return SourceTypeS3
	case "url", "SOURCE_TYPE_URL":
		return SourceTypeURL
	default:
		return SourceTypeUnspecified
	}
}

// FromInt32 creates a SourceType from an int32 value.
func FromInt32(i int32) SourceType {
	switch i {
	case 1:
		return SourceTypeGitHub
	case 2:
		return SourceTypeS3
	case 3:
		return SourceTypeURL
	default:
		return SourceTypeUnspecified
	}
}
