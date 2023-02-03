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
	IncludeStatusInCli
)

var featureMap map[Feature]MetadataConstraint

// Binary is the version of the running binary.
// This can be used for feature checks.
var Binary *gvers.Version

func init() {
	// Do this early to ensure version is valid, if this panics something is
	// very broken with the version and any version checks based on the binary's
	// version info will not work correctly. Also do this once since the version
	// can't change while running.
	var err error
	Binary, err = GetReleaseVersion()
	if err != nil {
		panic(err)
	}

	if featureMap == nil {
		featureMap = make(map[Feature]MetadataConstraint)
	}
	/*
		Add constraints here following this format after adding a Feature to the Feature iota:
		featureMap[FEATURE] = MetadataConstraint{
			MetaInfo:    []Metadata{OSS, HCP},
			Constraints: mustNewConstraints(">= 0.1.0"), // This feature exists at 0.1.0 and above
		}
	*/
	featureMap[IncludeStatusInCli] = MetadataConstraint{
		MetaInfo:    []Metadata{OSS, HCP},
		Constraints: mustNewConstraints("< 0.14.0"),
	}
}

func metadataStringToMetadata(m string) Metadata {
	if strings.Contains(strings.ToLower(m), "hcp") {
		return HCP
	}

	return OSS
}

func mustNewConstraints(v string) gvers.Constraints {
	c, err := gvers.NewConstraint(v)
	if err != nil {
		panic(err)
	}
	return c
}

// Check returns a bool indicating if a version meets the metadata constraint
// for a feature. Check returns false if version is nil.
func (m MetadataConstraint) Check(version *gvers.Version) bool {
	if version == nil {
		return false
	}
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
	return gvers.NewVersion(ver.VersionNumber())
}
