package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserPasswordMap(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.PublicId, 1)[0]
	lib := TestCredentialLibraries(t, conn, wrapper, cs.PublicId, 1)[0]

	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()

	// Validate the UserPasswordMap struct can be saved to the database.
	u := NewUserPasswordMap(lib.GetPublicId(), "v_username", "v_password")
	require.NotNil(u)

	id, err := newUsernamePasswordMapId(ctx)
	assert.NoError(err)

	u.PrivateId = id

	err2 := rw.Create(ctx, u)
	assert.NoError(err2)
}
