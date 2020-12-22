package schema

import (
	"context"

	"github.com/hashicorp/boundary/internal/db/schema/postgres"
)

const nilVersion = -1

// State contains information regarding the current state of a boundary database's schema.
type State struct {
	InitializationStarted bool
	Dirty                 bool
	CurrentSchemaVersion  int
	BinarySchemaVersion   int
}

// State provides the state of the boundary schema contained in the backing database.
func (b *Manager) State(ctx context.Context) (*State, error) {
	dbS := State{
		BinarySchemaVersion: BinarySchemaVersion(b.dialect),
	}
	v, dirty, err := b.driver.Version(ctx)
	if err != nil {
		return nil, err
	}
	if v == nilVersion {
		return &dbS, nil
	}
	dbS.InitializationStarted = true
	dbS.CurrentSchemaVersion = v
	dbS.Dirty = dirty
	return &dbS, nil
}

func DevMigration(dialect string) bool {
	return postgres.DevMigration
}

func BinarySchemaVersion(dialect string) int {
	return postgres.BinarySchemaVersion
}
