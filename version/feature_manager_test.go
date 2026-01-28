// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package version

import (
	"testing"

	gvers "github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasFeature_AllMetaData(t *testing.T) {
	DeprecatedFeature := Feature(999)
	ActiveFeature := Feature(998)

	deprecatedFeatureConstraint, _ := gvers.NewConstraint(">= 0.10.0, < 0.10.1")
	featureMap[DeprecatedFeature] = MetadataConstraint{
		Constraints: deprecatedFeatureConstraint,
	}
	activeFeatureConstraint, _ := gvers.NewConstraint("> 0.10.0")
	featureMap[ActiveFeature] = MetadataConstraint{
		Constraints: activeFeatureConstraint,
	}
	t.Cleanup(func() {
		delete(featureMap, DeprecatedFeature)
		_, ok := featureMap[DeprecatedFeature]
		require.False(t, ok)

		delete(featureMap, ActiveFeature)
		_, ok = featureMap[ActiveFeature]
		require.False(t, ok)
	})

	tests := []struct {
		name       string
		version    string
		feature    Feature
		wantResult bool
	}{
		{
			name:       "active-feature-before-active",
			version:    "0.10.0",
			feature:    ActiveFeature,
			wantResult: false,
		},
		{
			name:       "active-feature-after-active",
			version:    "0.12.0",
			feature:    ActiveFeature,
			wantResult: true,
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
}

func TestEnableFeatureOnVersionForTest_AllMetaData(t *testing.T) {
	FutureFeature := Feature(997)

	futureVersionFeature, _ := gvers.NewConstraint(">= 99.99.99")
	featureMap[FutureFeature] = MetadataConstraint{
		Constraints: futureVersionFeature,
	}
	t.Cleanup(func() {
		delete(featureMap, FutureFeature)
		_, ok := featureMap[FutureFeature]
		require.False(t, ok)
	})

	tests := []struct {
		name       string
		version    string
		feature    Feature
		wantResult bool
		wantErr    bool
	}{
		{
			name:       "has-future-feature",
			version:    "0.11.1",
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
}

func TestEnableFeatureForTest_AllMetaData(t *testing.T) {
	FutureFeature := Feature(997)

	futureVersionFeature, _ := gvers.NewConstraint(">= 99.99.99")
	featureMap[FutureFeature] = MetadataConstraint{
		Constraints: futureVersionFeature,
	}
	t.Cleanup(func() {
		delete(featureMap, FutureFeature)
		_, ok := featureMap[FutureFeature]
		require.False(t, ok)
	})

	// modify the globals that set which version the current binary is
	prevVer := Version
	defer func() {
		Version = prevVer
	}()
	Version = "0.11.0"

	EnableFeatureForTest(t, FutureFeature)

	semVer, err := gvers.NewVersion("0.11.0")
	require.NoError(t, err)
	assert.True(t, SupportsFeature(semVer, FutureFeature))
}
