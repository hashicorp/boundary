// Package oss is used to embed the sql statements for the oss edition and
// registering the edition for the schema.Manager.
package oss

import (
	"embed"

	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/hashicorp/boundary/internal/db/schema/migration"
)

// postgres contains the migrations sql files for postgres oss edition
//go:embed postgres
var postgres embed.FS

var prehooks = map[int]*migration.Hook{}

func init() {
	schema.RegisterEdition("oss", schema.Postgres, postgres, 0, edition.WithPreHooks(prehooks))
}
