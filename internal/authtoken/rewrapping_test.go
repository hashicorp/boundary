package authtoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
)

func TestRewrap_authTokenRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	// TestAuthToken will create and store the token for us
	at := TestAuthToken(t, conn, kmsCache, org.GetPublicId())

	// now things are stored in the db, we can rotate and rewrap
	assert.NoError(t, kmsCache.RotateKeys(ctx, org.Scope.GetPublicId()))
	assert.NoError(t, authTokenRewrapFn(ctx, at.GetKeyId(), rw, rw, kmsCache))

	// now we pull the authToken back from the db, decrypt it with the new key, and ensure things match
	got := allocAuthToken()
	got.PublicId = at.GetPublicId()
	assert.NoError(t, rw.LookupById(ctx, got))

	// fetch the new key version
	kmsWrapper, err := kmsCache.GetWrapper(ctx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
	assert.NoError(t, err)
	newKeyVersionId, err := kmsWrapper.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	assert.NoError(t, got.decrypt(ctx, kmsWrapper))
	assert.NotEmpty(t, got.GetKeyId())
	assert.NotEqual(t, at.GetKeyId(), got.GetKeyId())
	assert.Equal(t, newKeyVersionId, got.GetKeyId())
	assert.Equal(t, at.GetToken(), got.GetToken())
	assert.NotEqual(t, at.GetCtToken(), got.GetCtToken())
}
