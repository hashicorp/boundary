// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package version

import (
	"bytes"
	"fmt"
	"strings"

	gvers "github.com/hashicorp/go-version"
)

const BoundaryPrefix = "Boundary v"

// Info
type Info struct {
	Revision          string `json:"revision,omitempty"`
	Version           string `json:"version,omitempty"`
	VersionPrerelease string `json:"version_prerelease,omitempty"`
	VersionMetadata   string `json:"version_metadata,omitempty"`
	BuildDate         string `json:"build_date,omitempty"`
	CgoEnabled        bool   `json:"cgo_enabled,omitempty"`
}

func Get() *Info {
	ver := Version
	rel := VersionPrerelease
	md := VersionMetadata
	bd := BuildDate
	if GitDescribe != "" {
		ver = GitDescribe
	}
	if GitDescribe == "" && rel == "" && VersionPrerelease != "" {
		rel = "dev"
	}
	// Remove metadata string from version output for oss
	if md == "oss" {
		md = ""
	}

	return &Info{
		CgoEnabled:        CgoEnabled,
		Revision:          GitCommit,
		Version:           ver,
		VersionPrerelease: rel,
		VersionMetadata:   md,
		BuildDate:         bd,
	}
}

func (c *Info) VersionNumber() string {
	if Version == "unknown" && VersionPrerelease == "unknown" {
		return "(version unknown)"
	}

	version := c.Version

	if c.VersionPrerelease != "" {
		version = fmt.Sprintf("%s-%s", version, c.VersionPrerelease)
	}

	if c.VersionMetadata != "" && c.VersionMetadata != "oss" {
		version = fmt.Sprintf("%s+%s", version, c.VersionMetadata)
	}

	return version
}

// Semver returns a *gvers.Version if the Info is parseable as
// a semantic version. Otherwise it returns nil.
func (c *Info) Semver() *gvers.Version {
	if c == nil {
		return nil
	}
	v, err := gvers.NewSemver(c.VersionNumber())
	if err != nil {
		return nil
	}
	return v
}

// FromVersionString returns an *Info containing the version, or nil if the
// string was unable to be parsed.
func FromVersionString(s string) *Info {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, BoundaryPrefix)
	i := Info{}

	// Get the revision
	startOfRevIdx := strings.LastIndex(s, "(")
	endOfRevIdx := strings.LastIndex(s, ")")
	if startOfRevIdx > 0 && endOfRevIdx > 0 {
		if endOfRevIdx < startOfRevIdx {
			return nil
		}
		i.Revision, s = s[startOfRevIdx+1:endOfRevIdx], strings.TrimSpace(s[:startOfRevIdx])
	}

	v, err := gvers.NewSemver(s)
	if err != nil {
		return nil
	}

	if md := v.Metadata(); len(md) > 0 && md != "oss" {
		i.VersionMetadata = md
	}
	if pr := v.Prerelease(); len(pr) > 0 {
		i.VersionPrerelease = pr
	}
	i.Version = v.Core().String()

	return &i
}

func (c *Info) FullVersionNumber(rev bool) string {
	var versionString bytes.Buffer

	if Version == "unknown" && VersionPrerelease == "unknown" {
		return "Boundary (version unknown)"
	}

	fmt.Fprintf(&versionString, "%s%s", BoundaryPrefix, c.Version)
	if c.VersionPrerelease != "" {
		fmt.Fprintf(&versionString, "-%s", c.VersionPrerelease)
	}

	if c.VersionMetadata != "" && c.VersionMetadata != "oss" {
		fmt.Fprintf(&versionString, "+%s", c.VersionMetadata)
	}

	if rev && c.Revision != "" {
		fmt.Fprintf(&versionString, " (%s)", c.Revision)
	}

	return versionString.String()
}
