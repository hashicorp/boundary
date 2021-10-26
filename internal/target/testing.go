package target

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/require"
)

// TestNewCredentialLibrary creates a new in memory CredentialLibrary
// representing the relationship between targetId and credentialLibraryId with
// the given purpose.
func TestNewCredentialLibrary(targetId, credentialLibraryId string, purpose credential.Purpose) *CredentialLibrary {
	return &CredentialLibrary{
		CredentialLibrary: &store.CredentialLibrary{
			TargetId:            targetId,
			CredentialLibraryId: credentialLibraryId,
			CredentialPurpose:   string(purpose),
		},
	}
}

// TestCredentialLibrary creates a CredentialLibrary for targetId and
// libraryId with the credential purpose of application.
func TestCredentialLibrary(t *testing.T, conn *db.DB, targetId, libraryId string) *CredentialLibrary {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	lib := TestNewCredentialLibrary(targetId, libraryId, credential.ApplicationPurpose)
	err := rw.Create(context.Background(), lib)
	require.NoError(err)
	return lib
}
