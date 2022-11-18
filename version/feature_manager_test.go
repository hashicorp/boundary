package version

import (
	"testing"

	gvers "github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasFeature(t *testing.T) {
	t.Parallel()

	DeprecatedFeature := Feature(999)
	HCPOnlyFeature := Feature(998)

	deprecatedFeatureConstraint, _ := gvers.NewConstraint(">= 0.10.0, < 0.10.1")
	featureMap[DeprecatedFeature] = MetadataConstraint{
		MetaInfo:    []Metadata{OSS, HCP},
		Constraints: deprecatedFeatureConstraint,
	}

	hcpOnlyFeature, _ := gvers.NewConstraint(">= 0.12.0+hcp")
	featureMap[HCPOnlyFeature] = MetadataConstraint{
		MetaInfo:    []Metadata{HCP},
		Constraints: hcpOnlyFeature,
	}

	tests := []struct {
		name       string
		version    string
		feature    Feature
		wantResult bool
	}{
		{
			name:       "does-not-have-multihop-ENT",
			version:    "0.11.1+hcp",
			feature:    HCPOnlyFeature,
			wantResult: false,
		},
		{
			name:       "has-multihop-ENT",
			version:    "0.12.0+hcp",
			feature:    HCPOnlyFeature,
			wantResult: true,
		},
		{
			name:       "has-multihop-worker-ENT",
			version:    "0.12.0+hcp.int",
			feature:    HCPOnlyFeature,
			wantResult: true,
		},
		{
			name:       "does-not-have-multihop-OSS",
			version:    "0.12.0",
			feature:    HCPOnlyFeature,
			wantResult: false,
		},
		{
			name:       "deprecated-feature-before-deprecation",
			version:    "0.10.0",
			feature:    DeprecatedFeature,
			wantResult: true,
		},
		{
			name:       "deprecated-feature-after-deprecation",
			version:    "0.12.0",
			feature:    DeprecatedFeature,
			wantResult: false,
		},
		{
			name:       "bogus-feature",
			version:    "0.12.0",
			feature:    Feature(-1),
			wantResult: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testVersion, err := gvers.NewVersion(tt.version)
			assert.NoError(err)
			got := SupportsFeature(testVersion, tt.feature)
			require.Equal(tt.wantResult, got)
		})
	}
	delete(featureMap, DeprecatedFeature)
	_, ok := featureMap[DeprecatedFeature]
	require.False(t, ok)

	delete(featureMap, HCPOnlyFeature)
	_, ok = featureMap[HCPOnlyFeature]
	require.False(t, ok)
}

func TestEnableFeatureForTest(t *testing.T) {
	t.Parallel()

	FutureFeature := Feature(997)

	futureVersionFeature, _ := gvers.NewConstraint(">= 99.99.99+hcp")
	featureMap[FutureFeature] = MetadataConstraint{
		MetaInfo:    []Metadata{HCP},
		Constraints: futureVersionFeature,
	}

	tests := []struct {
		name       string
		version    string
		feature    Feature
		wantResult bool
		wantErr    bool
	}{
		{
			name:       "has-future-feature",
			version:    "0.11.1+hcp",
			feature:    FutureFeature,
			wantResult: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testVersion, err := gvers.NewVersion(tt.version)
			assert.NoError(err)

			testFunc := func() bool {
				EnableFeatureOnVersionForTest(t, testVersion, tt.feature)
				got := SupportsFeature(testVersion, tt.feature)
				return got
			}
			// Test that the feature was enabled
			got := testFunc()
			require.Equal(tt.wantResult, got)
		})
	}
	delete(featureMap, FutureFeature)
	_, ok := featureMap[FutureFeature]
	require.False(t, ok)
}
