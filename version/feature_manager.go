// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package version

import (
	gvers "github.com/hashicorp/go-version"
)

type MetadataConstraint struct {
	Constraints gvers.Constraints
}

type Feature int

const (
	UnknownFeature Feature = iota
	MultiHopSessionFeature
	IncludeStatusInCli
	CredentialLibraryVaultSubtype
	UseTargetIdForHostId
	RequireVersionInWorkerInfo
	SshSessionRecording
	SupportIdInGrants
	PluginDelete
	LocalStorageState
	StorageBucketCredentialState
	RDPSessionProxy
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
		Constraints: mustNewConstraints("< 0.14.0"),
	}
	featureMap[CredentialLibraryVaultSubtype] = MetadataConstraint{
		Constraints: mustNewConstraints("< 0.14.0"),
	}

	// UseTargetIdForHostId supports old CLI clients that are unaware of host-sourceless targets,
	// this feature populates the target's public id into the AuthorizeSessionResponse
	// and the SessionAuthorizationData so the CLI can properly build the ssh command
	// when calling "boundary connect ssh..."
	featureMap[UseTargetIdForHostId] = MetadataConstraint{
		Constraints: mustNewConstraints("< 0.14.0"),
	}
	// RequireVersionInWorkerInfo allows us to take action on various workers
	// based on their version, e.g. to prevent incompatibilities
	featureMap[RequireVersionInWorkerInfo] = MetadataConstraint{
		Constraints: mustNewConstraints(">= 0.13.0"),
	}
	featureMap[SshSessionRecording] = MetadataConstraint{
		Constraints: mustNewConstraints(">= 0.13.0"),
	}

	// Warn until 0.16 about using the now-deprecated id field in grants; after
	// that disallow it
	featureMap[SupportIdInGrants] = MetadataConstraint{
		Constraints: mustNewConstraints("< 0.15.0"),
	}

	// PluginDelete supports calling DeleteObjects on the Storage Plugin
	featureMap[PluginDelete] = MetadataConstraint{
		Constraints: mustNewConstraints(">= 0.15.0"),
	}

	// Worker supports reporting local storage state
	featureMap[LocalStorageState] = MetadataConstraint{
		Constraints: mustNewConstraints(">= 0.16.0"),
	}

	// Worker supports reporting the state of storage bucket credentials
	featureMap[StorageBucketCredentialState] = MetadataConstraint{
		Constraints: mustNewConstraints(">= 0.17.0"),
	}

	// Worker supports RDP session proxy
	featureMap[RDPSessionProxy] = MetadataConstraint{
		Constraints: mustNewConstraints(">= 0.20.0"),
	}
}

func mustNewConstraints(v string) gvers.Constraints {
	c, err := gvers.NewConstraint(v)
	if err != nil {
		panic(err)
	}
	return c
}

// Check returns a bool indicating if a version meets the constraints
// for a feature. Check returns false if version is nil.
func (m MetadataConstraint) Check(version *gvers.Version) bool {
	if version == nil {
		return false
	}
	return m.Constraints.Check(version)
}

// Check returns a bool indicating if a version satisfies the feature constraints
func Check(binaryVersion *gvers.Version, featureConstraint MetadataConstraint) bool {
	return featureConstraint.Check(binaryVersion)
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
