// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package edition_test

import (
	"embed"
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/stretchr/testify/assert"
)

// valid embed.FS
var (
	//go:embed testdata/one
	one embed.FS
	//go:embed testdata/two
	two embed.FS
	//go:embed testdata/three
	three embed.FS
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		priority               int
		fs                     embed.FS
		expectedVersion        int
		expectedMigrationCount int
	}{
		{
			"one",
			0,
			one,
			1,
			1,
		},
		{
			"two",
			1,
			two,
			2,
			2,
		},
		{
			"three",
			3,
			three,
			1001,
			2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := edition.New(tt.name, edition.Dialect("postgres"), tt.fs, tt.priority)
			assert.NoError(t, err)
			assert.Equal(t, e.Name, tt.name, "Name")
			assert.Equal(t, e.Dialect, edition.Dialect("postgres"), "Dialect")
			assert.Equal(t, e.LatestVersion, tt.expectedVersion, "Version")
			assert.Equal(t, e.Priority, tt.priority, "Priority")
			assert.Equal(t, len(e.Migrations), tt.expectedMigrationCount, "Number of migrations")
			for _, m := range e.Migrations {
				assert.NotContains(t, string(m.Statements), "begin;")
				assert.NotContains(t, string(m.Statements), "commit;")
			}
		})
	}
}

// invalid embed.FS
var (
	//go:embed testdata/invalid/major-version-not-int
	majorVersionNotInt embed.FS
	//go:embed testdata/invalid/minor-version-invalid-separator
	minorVersionInvalidSeparator embed.FS
	//go:embed testdata/invalid/minor-version-not-int
	minorVersionNotInt embed.FS
	//go:embed testdata/invalid/no-minor-version
	noMinorVersion embed.FS
	//go:embed testdata/invalid/no-major-version
	noMajorVersion embed.FS
	//go:embed testdata/invalid/duplicate-versions
	duplicateVersions embed.FS
)

func TestNewErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fs   embed.FS
	}{
		{
			"majorVersionNotInt",
			majorVersionNotInt,
		},
		{
			"minorVersionInvalidSeparator",
			minorVersionInvalidSeparator,
		},
		{
			"minorVersionNotInt",
			minorVersionNotInt,
		},
		{
			"noMinorVersion",
			noMinorVersion,
		},
		{
			"noMajorVersion",
			noMajorVersion,
		},
		{
			"duplicateVersions",
			duplicateVersions,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := edition.New(tt.name, edition.Dialect("postgres"), tt.fs, 0)
			assert.Error(t, err)
		})
	}
}

func TestSort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		editions edition.Editions
		sorted   edition.Editions
	}{
		{
			"unsortedConsecutive",
			edition.Editions{
				{
					Name:     "two",
					Priority: 2,
				},
				{
					Name:     "zero",
					Priority: 0,
				},
				{
					Name:     "one",
					Priority: 1,
				},
			},
			edition.Editions{
				{
					Name:     "zero",
					Priority: 0,
				},
				{
					Name:     "one",
					Priority: 1,
				},
				{
					Name:     "two",
					Priority: 2,
				},
			},
		},
		{
			"unsorted",
			edition.Editions{
				{
					Name:     "three",
					Priority: 3,
				},
				{
					Name:     "zero",
					Priority: 0,
				},
				{
					Name:     "one",
					Priority: 1,
				},
			},
			edition.Editions{
				{
					Name:     "zero",
					Priority: 0,
				},
				{
					Name:     "one",
					Priority: 1,
				},
				{
					Name:     "three",
					Priority: 3,
				},
			},
		},
		{
			"equalPriority",
			edition.Editions{
				{
					Name:     "three-also",
					Priority: 3,
				},
				{
					Name:     "three",
					Priority: 3,
				},
				{
					Name:     "zero",
					Priority: 0,
				},
				{
					Name:     "one",
					Priority: 1,
				},
			},
			edition.Editions{
				{
					Name:     "zero",
					Priority: 0,
				},
				{
					Name:     "one",
					Priority: 1,
				},
				{
					Name:     "three-also",
					Priority: 3,
				},
				{
					Name:     "three",
					Priority: 3,
				},
			},
		},
		{
			"alreadySorted",
			edition.Editions{
				{
					Name:     "zero",
					Priority: 0,
				},
				{
					Name:     "one",
					Priority: 1,
				},
				{
					Name:     "two",
					Priority: 2,
				},
			},
			edition.Editions{
				{
					Name:     "zero",
					Priority: 0,
				},
				{
					Name:     "one",
					Priority: 1,
				},
				{
					Name:     "two",
					Priority: 2,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.editions.Sort()
			assert.Equal(t, tt.editions, tt.sorted)
		})
	}
}
