package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/stretchr/testify/assert"
)

func TestRewrap_credStaticUsernamePasswordRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	secret, err := newHostCatalogSecret(ctx, cat.GetPublicId(), mustStruct(map[string]interface{}{
		"foo": "bar",
	}))
	assert.NoError(t, err)
	assert.NotNil(t, secret)
	assert.Empty(t, secret.CtSecret)
	assert.NotEmpty(t, secret.Secret)

	kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	secretSecret := secret.GetSecret() // this is cleared by the encrypt function, so save it for assert
	assert.NoError(t, secret.encrypt(ctx, kmsWrapper))
	assert.NoError(t, rw.Create(context.Background(), secret))

	// now things are stored in the db, we can rotate and rewrap
	assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
	assert.NoError(t, hostCatalogSecretRewrapFn(ctx, secret.GetKeyId(), rw, rw, kmsCache))

	// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
	got := allocHostCatalogSecret()
	got.CatalogId = cat.GetPublicId()
	assert.NoError(t, rw.LookupById(ctx, got))

	kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
	assert.NoError(t, err)
	assert.NoError(t, got.decrypt(ctx, kmsWrapper2))

	newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	assert.NotEmpty(t, got.GetKeyId())
	assert.NotEqual(t, secret.GetKeyId(), got.GetKeyId())
	assert.Equal(t, newKeyVersionId, got.GetKeyId())
	assert.Equal(t, secretSecret, got.GetSecret())
	assert.NotEqual(t, secret.GetCtSecret(), got.GetCtSecret())
}
