package schema

import (
	"context"
	"database/sql"

	"github.com/hashicorp/boundary/internal/errors"
)

// MigrateStore executes the migrations needed to initialize the store. It
// returns true if migrations actually ran; false if the database is already current
// or if there was an error.
func MigrateStore(ctx context.Context, dialect string, url string) (bool, error) {
	const op = "schema.MigrateStore"

	d, err := sql.Open(dialect, url)
	if err != nil {
		return false, errors.Wrap(err, op)
	}

	sMan, err := NewManager(ctx, dialect, d)
	if err != nil {
		return false, errors.Wrap(err, op)
	}

	st, err := sMan.CurrentState(ctx)
	if err != nil {
		return false, errors.Wrap(err, op)
	}
	if st.Dirty {
		return false, errors.New(errors.MigrationIntegrity, op, "db marked dirty")
	}

	if st.InitializationStarted && st.DatabaseSchemaVersion == st.BinarySchemaVersion {
		return false, nil
	}

	if err := sMan.RollForward(ctx); err != nil {
		return false, errors.Wrap(err, op)
	}

	return true, nil
}
