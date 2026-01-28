// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package version

var (
	// GitCommit is the git commit that was compiled. This will be filled in by the compiler.
	GitCommit   string
	GitDescribe string

	// CgoEnabled is whether cgo is enabled or not; set at build time
	CgoEnabled bool

	// Version is the base version
	// Default values - set when building locally (at build time)
	Version = "0.15.0"

	// VersionPrerelease is also set at compile time, similarly to Version.
	VersionPrerelease string

	// VersionMetadata is also set at compile time.
	VersionMetadata string

	// BuildDate is the date of the build, which corresponds to the timestamp of
	// the most recent commit
	BuildDate string
)
