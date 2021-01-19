package schema

import (
	"context"
	"database/sql"

	"github.com/hashicorp/boundary/internal/errors"
)

// MigrateStore executes the migrations needed to initialize the store. It
// returns true if migrations actually ran; false if the database is already current
// or if there was an error.
func MigrateStore(ctx context.Context, dialect string, url string, opt ...option) (bool, error) {
	const op = "schema.MigrateStore"
	opts := getOpts(opt...)

	d, err := sql.Open(dialect, url)
	if err != nil {
		return false, errors.Wrap(err, op)
	}

	sMan, err := NewManager(ctx, dialect, d)
	if err != nil {
		return false, errors.Wrap(err, op)
	}

	if !opts.skipSetDirty {
		sMan.SetDirty(ctx)
	}

	st, err := sMan.CurrentState(ctx)
	if err != nil {
		return false, errors.Wrap(err, op)
	}
	if !st.Dirty {
		return false, errors.New(errors.MigrationIntegrity, op, "db not marked dirty when migrating")
	}

	if st.InitializationStarted && st.DatabaseSchemaVersion == st.BinarySchemaVersion {
		return false, nil
	}

	if err := sMan.RollForward(ctx); err != nil {
		return false, errors.Wrap(err, op)
	}

	if !opts.skipUnsetDirty {
		sMan.UnsetDirty(ctx)
	}
	return true, nil
}

// getOpts - iterate the inbound options and return a struct.
func getOpts(opt ...option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// option - how options are passed as arguments.
type option func(*options)

// options - how options are represented.
type options struct {
	skipSetDirty, skipUnsetDirty bool
}

func getDefaultOptions() options {
	return options{}
}

// WithSkipUnsetDirty doesn't unset dirty when the migration is completed.
func WithSkipUnsetDirty(b bool) option {
	return func(o *options) {
		o.skipUnsetDirty = b
	}
}

// WithSkipSetDirty doesn't set dirty before migrating the data.
func WithSkipSetDirty(b bool) option {
	return func(o *options) {
		o.skipSetDirty = b
	}
}
