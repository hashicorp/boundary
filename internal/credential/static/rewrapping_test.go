package static

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
)

func TestRewrap_credStaticUsernamePasswordRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)
	cred, err := NewUsernamePasswordCredential(cs.GetPublicId(), "username", "password")
	assert.NoError(t, err)

	assert.NotNil(t, cred)
	assert.Emptyf(t, cred.PublicId, "PublicId set")

	id, err := credential.NewUsernamePasswordCredentialId(ctx)
	assert.NoError(t, err)

	cred.PublicId = id

	kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)

	err = cred.encrypt(ctx, kmsWrapper)
	assert.NoError(t, err)

	err = rw.Create(context.Background(), cred)
	assert.NoError(t, err)

	// now things are stored in the db, we can rotate and rewrap
	err = kmsCache.RotateKeys(ctx, prj.PublicId)
	assert.NoError(t, err)

	err = credStaticUsernamePasswordRewrapFn(ctx, cred.GetKeyId(), rw, rw, kmsCache)
	assert.NoError(t, err)

	// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
	got := allocUsernamePasswordCredential()
	got.PublicId = id
	assert.NoError(t, rw.LookupById(ctx, got))

	kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
	assert.NoError(t, err)

	err = got.decrypt(ctx, kmsWrapper2)
	assert.NoError(t, err)

	newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	assert.NotEmpty(t, got.GetKeyId())
	assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())
	assert.Equal(t, newKeyVersionId, got.GetKeyId())
	assert.Equal(t, "password", string(got.GetPassword()))
	assert.NotEmpty(t, got.GetPasswordHmac())
	assert.NotEqual(t, cred.GetPasswordHmac(), got.GetPasswordHmac())
}
