package static

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static/store"
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

	cred.PublicId, err = credential.NewUsernamePasswordCredentialId(ctx)
	assert.NoError(t, err)

	kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)

	assert.NoError(t, cred.encrypt(ctx, kmsWrapper))
	assert.NoError(t, rw.Create(context.Background(), cred))

	// now things are stored in the db, we can rotate and rewrap
	assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
	assert.NoError(t, credStaticUsernamePasswordRewrapFn(ctx, cred.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

	// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
	got := allocUsernamePasswordCredential()
	got.PublicId = cred.PublicId
	assert.NoError(t, rw.LookupById(ctx, got))

	kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
	assert.NoError(t, err)
	newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
	assert.NotEmpty(t, got.GetKeyId())
	assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())
	assert.Equal(t, newKeyVersionId, got.GetKeyId())
	assert.Equal(t, "password", string(got.GetPassword()))
	assert.NotEmpty(t, got.GetPasswordHmac())
	assert.Equal(t, cred.GetPasswordHmac(), got.GetPasswordHmac())
}

func TestRewrap_credStaticSshPrivKeyRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	// since there are two possible versions (with or without passphrase) we need to make 2 copies of everything, but rewrap only once
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)
	cs2 := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	cred, err := NewSshPrivateKeyCredential(ctx, cs.GetPublicId(), "username", credential.PrivateKey(TestSshPrivateKeyPem))
	assert.NoError(t, err)

	// we need to assign this one explicitly since the new function (correctly) has some checks on the passphrase actually being correct
	cred2 := &SshPrivateKeyCredential{
		SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
			StoreId:              cs2.GetPublicId(),
			Username:             "username",
			PrivateKey:           credential.PrivateKey(TestSshPrivateKeyPem),
			PrivateKeyPassphrase: []byte("passphrase"),
		},
	}

	cred.PublicId, err = credential.NewSshPrivateKeyCredentialId(ctx)
	assert.NoError(t, err)
	cred2.PublicId, err = credential.NewSshPrivateKeyCredentialId(ctx)
	assert.NoError(t, err)

	kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)

	assert.NoError(t, cred.encrypt(ctx, kmsWrapper))
	assert.NoError(t, cred2.encrypt(ctx, kmsWrapper))

	// create them in the db
	assert.NoError(t, rw.Create(context.Background(), cred))
	assert.NoError(t, rw.Create(context.Background(), cred2))

	// now things are stored in the db, we can rotate and rewrap
	assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
	assert.NoError(t, credStaticSshPrivKeyRewrapFn(ctx, cred.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

	// now we pull both credential2 back from the db, decrypt them with the new key, and ensure things match
	got := allocSshPrivateKeyCredential()
	got.PublicId = cred.PublicId
	assert.NoError(t, rw.LookupById(ctx, got))

	got2 := allocSshPrivateKeyCredential()
	got2.PublicId = cred2.PublicId
	assert.NoError(t, rw.LookupById(ctx, got2))

	kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
	assert.NoError(t, err)

	newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
	assert.NotEmpty(t, got.GetKeyId())
	assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())
	assert.Equal(t, newKeyVersionId, got.GetKeyId())
	assert.Equal(t, TestSshPrivateKeyPem, string(got.PrivateKey))
	assert.NotEqual(t, cred.GetPrivateKeyEncrypted(), got.GetPrivateKeyEncrypted())
	assert.NotEmpty(t, got.GetPrivateKeyHmac())
	assert.Equal(t, cred.GetPrivateKeyHmac(), got.GetPrivateKeyHmac())
	// we didn't set this, so they should be empty before AND after rewrapping
	assert.Empty(t, got.GetPrivateKeyPassphrase())
	assert.Empty(t, got.GetPrivateKeyPassphraseHmac())
	assert.Empty(t, got.GetPrivateKeyPassphraseEncrypted())

	// perform all the same checks again on #2, but also check passphrase
	assert.NoError(t, got2.decrypt(ctx, kmsWrapper2))
	assert.NotEmpty(t, got2.GetKeyId())
	assert.NotEqual(t, cred2.GetKeyId(), got2.GetKeyId())
	assert.Equal(t, newKeyVersionId, got2.GetKeyId())
	assert.Equal(t, TestSshPrivateKeyPem, string(got2.PrivateKey))
	assert.NotEqual(t, cred.GetPrivateKeyEncrypted(), got.GetPrivateKeyEncrypted())
	assert.NotEmpty(t, got2.GetPrivateKeyHmac())
	assert.Equal(t, cred2.GetPrivateKeyHmac(), got2.GetPrivateKeyHmac())
	// this time, we did set this, so they should be available
	assert.NotEmpty(t, got2.GetPrivateKeyPassphraseEncrypted())
	assert.NotEmpty(t, got2.GetPrivateKeyPassphraseHmac())
	assert.Equal(t, []byte("passphrase"), got2.GetPrivateKeyPassphrase())
	assert.Equal(t, cred2.GetPrivateKeyPassphraseHmac(), got2.GetPrivateKeyPassphraseHmac())
}
