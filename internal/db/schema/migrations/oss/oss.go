// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Package oss is used to embed the sql statements for the oss edition and
// registering the edition for the schema.Manager.
package oss

import (
	"embed"

	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/hashicorp/boundary/internal/db/schema/migration"
	"github.com/hashicorp/boundary/internal/db/schema/migrations/oss/internal/hook46001"
)

// postgres contains the migrations sql files for postgres oss edition
//
//go:embed postgres
var postgres embed.FS

var prehooks = map[int]*migration.Hook{
	46001: {
		CheckFunc:         hook46001.FindIllegalAssociations,
		RepairFunc:        hook46001.RepairIllegalAssociations,
		RepairDescription: hook46001.RepairDescription,
	},
}

func init() {
	schema.RegisterEdition("oss", schema.Postgres, postgres, 0, edition.WithPreHooks(prehooks))
}
