package schema

import (
	"context"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
)

// MigrateStore executes the migrations needed to initialize the store. It
// returns true if migrations actually ran; false if the database is already current
// or if there was an error.  Supports the WithMigrationStates(...) option.
func MigrateStore(ctx context.Context, dialect string, url string, opt ...Option) (bool, error) {
	const op = "schema.MigrateStore"

	d, err := common.SqlOpen(dialect, url)
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}

	sMan, err := NewManager(ctx, dialect, d, opt...)
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}

	st, err := sMan.CurrentState(ctx)
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}
	if st.Dirty {
		return false, errors.New(ctx, errors.MigrationIntegrity, op, "db marked dirty")
	}

	if st.InitializationStarted && st.DatabaseSchemaVersion == st.BinarySchemaVersion {
		return false, nil
	}

	if err := sMan.RollForward(ctx); err != nil {
		return false, errors.Wrap(ctx, err, op)
	}

	return true, nil
}
