package acl

import (
	"fmt"
	"strings"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// ScanningToEnumerationTranslator converts scanning domain objects to enumeration domain objects.
type ScanningToEnumerationTranslator struct{}

// ToEnumerationTargetSpec converts scanning Target and Auth to an enumeration TargetSpec.
func (ScanningToEnumerationTranslator) ToEnumerationTargetSpec(
	scanTarget scanning.Target,
	scanAuth scanning.Auth,
) (*enumeration.TargetSpec, error) {
	// Convert auth configuration.
	auth := enumeration.NewAuthSpec(
		scanAuth.Type(),
		scanAuth.Config(),
	)

	// Base target spec fields.
	spec := enumeration.NewTargetSpec(
		scanTarget.Name(),
		scanTarget.SourceType(),
		scanTarget.AuthID(),
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
		spec.SetGitHub(&enumeration.GitHubTargetSpec{
			Org:      scanTarget.Metadata()["org"],
			RepoList: strings.Split(scanTarget.Metadata()["repos"], ","),
			Metadata: scanTarget.Metadata(),
		})

	case shared.SourceTypeURL:
		spec.SetURL(&enumeration.URLTargetSpec{
			URLs:     strings.Split(scanTarget.Metadata()["urls"], ","),
			Metadata: scanTarget.Metadata(),
		})

	case shared.SourceTypeS3:
		spec.SetS3(&enumeration.S3TargetSpec{
			Bucket:   scanTarget.Metadata()["bucket"],
			Prefix:   scanTarget.Metadata()["prefix"],
			Region:   scanTarget.Metadata()["region"],
			Metadata: scanTarget.Metadata(),
		})

	default:
		return fmt.Errorf("unsupported target type: %s", scanTarget.SourceType())
	}

	return nil
}
