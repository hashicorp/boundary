// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package version

import (
	"testing"

	gvers "github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
)

func TestFromVersionString(t *testing.T) {
	cases := []struct {
		input string
		want  *Info
	}{
		{
			input: "Boundary v0.12.0-beta+hcp.int (revision)",
			want: &Info{
				Revision:          "revision",
				Version:           "0.12.0",
				VersionPrerelease: "beta",
				VersionMetadata:   "hcp.int",
			},
		},
		{
			input: "Boundary v0.12.0+hcp.int",
			want: &Info{
				Version:         "0.12.0",
				VersionMetadata: "hcp.int",
			},
		},
		{
			input: "Boundary v0.12.0",
			want: &Info{
				Version: "0.12.0",
			},
		},
		{
			input: "0.12.0-alpha+hcp.int (revision)",
			want: &Info{
				Revision:          "revision",
				Version:           "0.12.0",
				VersionPrerelease: "alpha",
				VersionMetadata:   "hcp.int",
			},
		},
		{
			input: " 0.12.0-hcp+int ",
			want: &Info{
				Version:           "0.12.0",
				VersionPrerelease: "hcp",
				VersionMetadata:   "int",
			},
		},
		{
			input: "0.12.0- spaces in the prerelease are invalid",
			want:  nil,
		},
		{
			input: "Boundary (version unknown)",
			want:  nil,
		},
		{
			input: "(version unknown)",
			want:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := FromVersionString(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSemver(t *testing.T) {
	cases := []struct {
		name   string
		toTest *Info
		want   *gvers.Version
	}{
		{
			name: "0.12.0+hcp.int",
			toTest: &Info{
				Version:         "0.12.0",
				VersionMetadata: "hcp.int",
			},
			want: gvers.Must(gvers.NewSemver("0.12.0+hcp.int")),
		},
		{
			name: "0.12.0+hcp.int (revision)",
			toTest: &Info{
				Version:         "0.12.0",
				VersionMetadata: "hcp.int",
				Revision:        "revision",
			},
			want: gvers.Must(gvers.NewSemver("0.12.0+hcp.int")),
		},
		{
			name: "unparsable",
			toTest: &Info{
				Version:         "some unparsable string",
				VersionMetadata: "hcp.int",
			},
			want: nil,
		},
		{
			name:   "nil info",
			toTest: nil,
			want:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.toTest.Semver()
			assert.Equal(t, tc.want, got)
		})
	}
}
