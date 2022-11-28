package version

import (
	"strings"

	gvers "github.com/hashicorp/go-version"
)

type Metadata int

const (
	OSS Metadata = iota
	HCP
)

type MetadataConstraint struct {
	MetaInfo    []Metadata
	Constraints gvers.Constraints
}

type Feature int

const (
	UnknownFeature Feature = iota
	MultiHopSessionFeature
)

var featureMap map[Feature]MetadataConstraint

func init() {
	if featureMap == nil {
		featureMap = make(map[Feature]MetadataConstraint)
	}
	/*
		Add constraints here following this format after adding a Feature to the Feature iota:
		featureConstraint, err := gvers.NewConstraint(">= 0.1.0") // This feature exists at 0.1.0 and above
		featureMap[FEATURE] = MetadataConstraint{
			MetaInfo:    []Metadata{OSS, HCP},
			Constraints: featureConstraint,
		}
	*/
}

func metadataStringToMetadata(m string) Metadata {
	if strings.Contains(strings.ToLower(m), "hcp") {
		return HCP
	}

	return OSS
}

// Check returns a bool indicating if a version meets the metadata constraint for a feature
func (m MetadataConstraint) Check(version *gvers.Version) bool {
	binaryMeta := metadataStringToMetadata(version.Metadata())

	for _, v := range m.MetaInfo {
		if v == binaryMeta {
			return true
		}
	}
	return false
}

// Check returns a bool indicating if a version satisfies the feature constraints
func Check(binaryVersion *gvers.Version, featureConstraint MetadataConstraint) bool {
	if !featureConstraint.Check(binaryVersion) {
		return false
	}

	return featureConstraint.Constraints.Check(binaryVersion)
}

// SupportsFeature return a bool indicating whether or not this version supports the given feature
func SupportsFeature(version *gvers.Version, feature Feature) bool {
	featureVersion, found := featureMap[feature]
	if !found {
		return false
	}

	return Check(version, featureVersion)
}

// GetReleaseVersion returns a go-version of this binary's Boundary version
func GetReleaseVersion() (*gvers.Version, error) {
	ver := Get()
	return gvers.NewVersion(ver.Version)
}
