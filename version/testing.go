package version

import (
	"fmt"
	"testing"

	gvers "github.com/hashicorp/go-version"
	"github.com/stretchr/testify/require"
)

func EnableFeatureForTest(t *testing.T, feature Feature) {
	require := require.New(t)
	version, err := GetReleaseVersion()
	require.NoError(err)
	EnableFeatureOnVersionForTest(t, version, feature)
}

// EnableFeatureForTest modifies the feature map to enable a feature for a version.
// This is intended to be used for testing before release of a version
// Test cleanup will reset the feature map to the original feature constraint
// Note: running any tests in parallel while using this function WILL result in surprising
// behavior because this modifies the global feature map
func EnableFeatureOnVersionForTest(t *testing.T, version *gvers.Version, feature Feature) {
	featConstraint, ok := featureMap[feature]
	require := require.New(t)
	require.True(ok)

	versionNumber := version.String()
	newConstraint, err := gvers.NewConstraint(fmt.Sprintf(">= %s", versionNumber))
	require.NoError(err)

	meta := metadataStringToMetadata(version.Metadata())
	featureMap[feature] = MetadataConstraint{
		MetaInfo:    []Metadata{meta},
		Constraints: newConstraint,
	}

	resetFunc := func() {
		featureMap[feature] = featConstraint
	}
	t.Cleanup(resetFunc)
}
