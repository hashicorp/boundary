package schema

import (
	"context"
	"database/sql"
	"fmt"
)

// InitStore will execute the migrations needed to initialize the store. It
// returns true if migrations actually ran; false if we were already current.
func InitStore(ctx context.Context, dialect string, url string) (bool, error) {
	d, err := sql.Open(dialect, url)
	if err != nil {
		return false, err
	}

	sMan, err := NewManager(ctx, dialect, d)
	if err != nil {
		return false, err
	}

	st, err := sMan.CurrentState(ctx)
	if err != nil {
		return false, err
	}
	if st.Dirty {
		return false, fmt.Errorf("The passed in database has had a failed migration applied to it.")
	}

	if st.InitializationStarted && st.CurrentSchemaVersion == st.BinarySchemaVersion {
		return false, nil
	}

	if err := sMan.RollForward(ctx); err != nil {
		return false, err
	}
	return true, nil
}
