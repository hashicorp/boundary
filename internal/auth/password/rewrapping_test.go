package password

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewrap_argon2ConfigRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	auts := TestAuthMethods(t, conn, org.GetPublicId(), 1)
	aut := auts[0]
	acct := TestAccount(t, conn, aut.PublicId, "name")
	authMethodId := acct.AuthMethodId
	conf := testArgon2Confs(t, conn, authMethodId, 1)[0]

	kmsCache := kms.TestKms(t, conn, wrapper)
	wrapper, _ = kmsCache.GetWrapper(context.Background(), org.GetPublicId(), 1)

	// actually store it
	cred, err := newArgon2Credential(acct.PublicId, "this is a password", conf)
	require.NoError(t, err)

	require.NoError(t, cred.encrypt(context.Background(), wrapper))
	assert.NoError(t, rw.Create(context.Background(), cred))

	// now things are stored in the db, we can rotate and rewrap
	assert.NoError(t, kmsCache.RotateKeys(ctx, org.Scope.GetPublicId()))
	assert.NoError(t, argon2ConfigRewrapFn(ctx, cred.KeyId, rw, rw, kmsCache))

	// now we pull the config back from the db, decrypt it with the new key, and ensure things match
	got := &Argon2Credential{
		Argon2Credential: &store.Argon2Credential{
			PrivateId: cred.PrivateId,
		},
	}
	assert.NoError(t, rw.LookupById(ctx, got))

	// fetch the new key version
	kmsWrapper, err := kmsCache.GetWrapper(ctx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
	assert.NoError(t, err)
	newKeyVersion, err := kmsWrapper.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	assert.NoError(t, got.decrypt(ctx, kmsWrapper))
	assert.NotEmpty(t, got.GetKeyId())
	assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())
	assert.Equal(t, newKeyVersion, got.GetKeyId())
	assert.Equal(t, cred.GetSalt(), got.GetSalt())
	assert.NotEqual(t, cred.GetCtSalt(), got.GetCtSalt())
}
