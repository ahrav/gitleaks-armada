package acl

import (
	"fmt"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// ScanningToEnumerationTranslator converts scanning domain objects to enumeration domain objects.
type ScanningToEnumerationTranslator struct{}

// ToEnumerationTargetSpec converts a scanning Target to an enumeration TargetSpec.
func (ScanningToEnumerationTranslator) ToEnumerationTargetSpec(
	scanTarget scanning.Target,
) (*enumeration.TargetSpec, error) {
	// Convert auth if present.
	var auth *enumeration.AuthSpec
	if scanTarget.HasAuth() {
		auth = enumeration.NewAuthSpec(
			string(scanTarget.Auth().Type()),
			scanTarget.Auth().Credentials(),
		)
	}

	// Create base target spec.
	spec := enumeration.NewTargetSpec(
		scanTarget.Name(),
		scanTarget.SourceType(),
		auth,
	)

	// Build source-specific configuration based on target type.
	if err := enrichTargetSpec(spec, scanTarget); err != nil {
		return nil, fmt.Errorf("failed to enrich target spec: %w", err)
	}

	return spec, nil
}

// enrichTargetSpec adds source-specific configuration to the target spec.
func enrichTargetSpec(
	spec *enumeration.TargetSpec,
	scanTarget scanning.Target,
) error {
	switch scanTarget.SourceType() {
	case shared.SourceTypeGitHub:
		githubTarget := scanTarget.GitHub()
		if githubTarget == nil {
			return fmt.Errorf("missing GitHub configuration for GitHub target")
		}
		spec.SetGitHub(&enumeration.GitHubTargetSpec{
			Org:      githubTarget.Org(),
			RepoList: githubTarget.RepoList(),
		})

	case shared.SourceTypeS3:
		s3Target := scanTarget.S3()
		if s3Target == nil {
			return fmt.Errorf("missing S3 configuration for S3 target")
		}
		spec.SetS3(&enumeration.S3TargetSpec{
			Bucket: s3Target.Bucket(),
			Prefix: s3Target.Prefix(),
			Region: s3Target.Region(),
		})

	case shared.SourceTypeURL:
		urlTarget := scanTarget.URL()
		if urlTarget == nil {
			return fmt.Errorf("missing URL configuration for URL target")
		}
		// TODO: Handle other metadata fields.
		meta := scanTarget.Metadata()
		spec.SetURL(&enumeration.URLTargetSpec{
			URLs:          urlTarget.URLs(),
			ArchiveFormat: enumeration.ArchiveFormat(meta["archive_format"]),
		})

	default:
		return fmt.Errorf("unsupported target type: %s", scanTarget.SourceType())
	}

	return nil
}
