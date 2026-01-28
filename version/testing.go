// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package version

import (
	"fmt"
	"testing"

	gvers "github.com/hashicorp/go-version"
	"github.com/stretchr/testify/require"
)

// EnableFeatureForTest enables a feature for the current binary version
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

	featureMap[feature] = MetadataConstraint{
		Constraints: newConstraint,
	}

	t.Cleanup(func() {
		featureMap[feature] = featConstraint
	})
}
