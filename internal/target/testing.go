package target

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/require"
)

// TestCredentialLibrary creates a CredentialLibrary for targetId and
// libraryId.
func TestCredentialLibrary(t *testing.T, conn *db.DB, targetId, libraryId string) *CredentialLibrary {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	lib, err := NewCredentialLibrary(targetId, libraryId)
	require.NoError(err)
	err = rw.Create(context.Background(), lib)
	require.NoError(err)
	return lib
}
