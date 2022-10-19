package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
)

func TestRewrap_credVaultClientCertificateRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId, "https://vault.consul.service", "token", "accessor")
	cert, err := NewClientCertificate([]byte(certPem), []byte(keyPem))
	assert.NoError(t, err)

	cert.StoreId = cs.PublicId

	kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	assert.NoError(t, cert.encrypt(ctx, kmsWrapper))
	assert.NoError(t, rw.Create(context.Background(), cert))

	// now things are stored in the db, we can rotate and rewrap
	assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
	assert.NoError(t, credVaultClientCertificateRewrapFn(ctx, cert.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

	// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
	got := allocClientCertificate()
	got.StoreId = cs.PublicId
	assert.NoError(t, rw.LookupById(ctx, got))

	kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
	assert.NoError(t, err)

	assert.NoError(t, got.decrypt(ctx, kmsWrapper2))

	newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	assert.NotEmpty(t, got.GetKeyId())
	assert.NotEqual(t, cert.GetKeyId(), got.GetKeyId())
	assert.Equal(t, newKeyVersionId, got.GetKeyId())
	assert.Equal(t, keyPem, string(got.GetCertificateKey()))
	assert.NotEmpty(t, got.GetCertificateKeyHmac())
	assert.Equal(t, cert.GetCertificateKeyHmac(), got.GetCertificateKeyHmac())
}

func TestRewrap_credVaultTokenRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId, "https://vault.consul.service", "token", "accessor")
	token := cs.outputToken

	// now things are stored in the db, we can rotate and rewrap
	assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
	assert.NoError(t, credVaultTokenRewrapFn(ctx, token.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

	// now we pull the token back from the db, decrypt it with the new key, and ensure things match
	got := allocToken()
	assert.NoError(t, rw.LookupWhere(ctx, &got, "store_id = ?", []interface{}{cs.PublicId}))

	kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
	assert.NoError(t, err)
	newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
	assert.NotEmpty(t, got.GetKeyId())
	assert.NotEqual(t, token.GetKeyId(), got.GetKeyId())
	assert.Equal(t, newKeyVersionId, got.GetKeyId())
	assert.Equal(t, "token", string(got.GetToken()))
	assert.NotEmpty(t, got.GetTokenHmac())
	// vault token hmacs are calculated differently and should remain the same
	assert.Equal(t, token.GetTokenHmac(), got.GetTokenHmac())
}
