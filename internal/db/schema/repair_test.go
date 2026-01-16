// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/stretchr/testify/assert"
)

func TestRepairMigrationsIsSet(t *testing.T) {
	cases := []struct {
		name    string
		m       schema.RepairMigrations
		edition string
		version int
		want    bool
	}{
		{
			name: "Set",
			m: schema.RepairMigrations{
				"one": {
					1: true,
				},
			},
			edition: "one",
			version: 1,
			want:    true,
		},
		{
			name: "VersionNotSet",
			m: schema.RepairMigrations{
				"one": {
					2: true,
				},
			},
			edition: "one",
			version: 1,
			want:    false,
		},
		{
			name: "EditionNotSet",
			m: schema.RepairMigrations{
				"two": {
					1: true,
				},
			},
			edition: "one",
			version: 1,
			want:    false,
		},
		{
			name:    "Empty",
			m:       schema.RepairMigrations{},
			edition: "one",
			version: 1,
			want:    false,
		},
		{
			name:    "Nil",
			m:       nil,
			edition: "one",
			version: 1,
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.m.IsSet(tc.edition, tc.version)
			assert.Equal(t, tc.want, got, tc.name)
		})
	}
}

func TestRepairMigrationsAdd(t *testing.T) {
	cases := []struct {
		name    string
		initial schema.RepairMigrations
		edition string
		version int
		want    schema.RepairMigrations
	}{
		{
			name:    "Empty",
			initial: schema.RepairMigrations{},
			edition: "one",
			version: 1,
			want: schema.RepairMigrations{
				"one": {
					1: true,
				},
			},
		},
		{
			name: "AlreadySet",
			initial: schema.RepairMigrations{
				"one": {
					1: true,
				},
			},
			edition: "one",
			version: 1,
			want: schema.RepairMigrations{
				"one": {
					1: true,
				},
			},
		},
		{
			name: "EditionExistsNewVersion",
			initial: schema.RepairMigrations{
				"one": {
					1: true,
				},
			},
			edition: "one",
			version: 2,
			want: schema.RepairMigrations{
				"one": {
					1: true,
					2: true,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.initial.Add(tc.edition, tc.version)
			got := tc.initial
			assert.Equal(t, tc.want, got, tc.name)
		})
	}
}
