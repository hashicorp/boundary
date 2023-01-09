package version

import (
	"bytes"
	"fmt"
)

const BoundaryPrefix = "Boundary v"

// Info
type Info struct {
	Revision          string `json:"revision,omitempty"`
	Version           string `json:"version,omitempty"`
	VersionPrerelease string `json:"version_prerelease,omitempty"`
	VersionMetadata   string `json:"version_metadata,omitempty"`
	CgoEnabled        bool   `json:"cgo_enabled,omitempty"`
}

func Get() *Info {
	ver := Version
	rel := VersionPrerelease
	md := VersionMetadata
	if GitDescribe != "" {
		ver = GitDescribe
	}
	if GitDescribe == "" && rel == "" && VersionPrerelease != "" {
		rel = "dev"
	}

	return &Info{
		CgoEnabled:        CgoEnabled,
		Revision:          GitCommit,
		Version:           ver,
		VersionPrerelease: rel,
		VersionMetadata:   md,
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

	if c.VersionMetadata != "" {
		version = fmt.Sprintf("%s+%s", version, c.VersionMetadata)
	}

	return version
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

	if c.VersionMetadata != "" {
		fmt.Fprintf(&versionString, "+%s", c.VersionMetadata)
	}

	if rev && c.Revision != "" {
		fmt.Fprintf(&versionString, " (%s)", c.Revision)
	}

	return versionString.String()
}
