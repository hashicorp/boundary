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
	got, err := newArgon2Credential(acct.PublicId, "this is a password", conf)
	require.NoError(t, err)

	err = got.encrypt(context.Background(), wrapper)
	require.NoError(t, err)
	err = rw.Create(context.Background(), got)
	assert.NoError(t, err)

	// now things are stored in the db, we can rotate and rewrap
	err = kmsCache.RotateKeys(ctx, org.Scope.GetPublicId())
	assert.NoError(t, err)

	err = argon2ConfigRewrapFn(ctx, got.KeyId, rw, rw, kmsCache)
	assert.NoError(t, err)

	// now we pull the config back from the db, decrypt it with the new key, and ensure things match
	cred := &Argon2Credential{
		Argon2Credential: &store.Argon2Credential{
			PrivateId: got.PrivateId,
		},
	}
	err = rw.LookupById(ctx, cred)
	assert.NoError(t, err)

	assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())

	// fetch the new key version
	kmsWrapper, err := kmsCache.GetWrapper(ctx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase, kms.WithKeyId(cred.GetKeyId()))
	assert.NoError(t, err)
	newKeyVersion, err := kmsWrapper.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	cred.decrypt(ctx, kmsWrapper)
	assert.Equal(t, cred.GetKeyId(), newKeyVersion)
	assert.Equal(t, got.GetSalt(), cred.GetSalt())
}
