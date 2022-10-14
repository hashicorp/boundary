package server

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/stretchr/testify/assert"
)

func TestRewrap_workerAuthCertRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestScopes(t, iam.TestRepo(t, conn, wrapper)) // despite not looking like it, this is necessary for some reason

	// create a repo and rotate to generate the first auth cert
	workerAuthRepo, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
	assert.NoError(t, err)
	roots, err := rotation.RotateRootCertificates(ctx, workerAuthRepo)
	assert.NoError(t, err)

	// pull this directly from the db rather than convert so we don't lose key info
	currentRoot := allocRootCertificate()
	assert.NoError(t, rw.SearchWhere(ctx, &currentRoot, "state = ?", []interface{}{"current"}, db.WithLimit(-1)))

	// now things are stored in the db, we can rotate and rewrap
	assert.NoError(t, kmsCache.RotateKeys(ctx, scope.Global.String()))
	assert.NoError(t, workerAuthCertRewrapFn(ctx, currentRoot.KeyId, scope.Global.String(), rw, rw, kmsCache))

	// now we pull the certs back from the db, decrypt it with the new key, and ensure things match
	got := allocRootCertificate()
	assert.NoError(t, rw.SearchWhere(ctx, &got, "state = ?", []interface{}{"current"}, db.WithLimit(-1)))

	kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
	assert.NoError(t, err)
	newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	decryptedGotPrivKey, err := decrypt(ctx, got.GetPrivateKey(), kmsWrapper2)
	assert.NoError(t, err)
	assert.NotEmpty(t, got.GetKeyId())
	assert.NotEqual(t, currentRoot.GetKeyId(), got.GetKeyId())
	assert.Equal(t, newKeyVersionId, got.GetKeyId())
	assert.NotEqual(t, currentRoot.GetPrivateKey(), got.GetPrivateKey())
	assert.Equal(t, roots.Current.PrivateKeyPkcs8, decryptedGotPrivKey)
}

func TestRewrap_workerAuthRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestScopes(t, iam.TestRepo(t, conn, wrapper)) // despite not looking like it, this is necessary for some reason

	worker := TestPkiWorker(t, conn, wrapper)
	kmsWrapper, err := kmsCache.GetWrapper(ctx, worker.GetScopeId(), kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	currentKeyId, err := kmsWrapper.KeyId(ctx)
	assert.NoError(t, err)
	workerAuth := TestWorkerAuth(t, conn, worker, currentKeyId)

	// TestWorkerAuth doesn't encrypt the entry, so do that really quick
	controllerEncryptionPrivKey := workerAuth.ControllerEncryptionPrivKey
	workerAuth.ControllerEncryptionPrivKey, err = encrypt(ctx, workerAuth.ControllerEncryptionPrivKey, kmsWrapper)
	assert.NoError(t, err)
	rows, err := rw.Update(ctx, workerAuth, []string{"ControllerEncryptionPrivKey"}, nil)
	assert.Equal(t, 1, rows)
	assert.NoError(t, err)

	// now things are stored in the db, we can rotate and rewrap
	assert.NoError(t, kmsCache.RotateKeys(ctx, scope.Global.String()))
	assert.NoError(t, workerAuthRewrapFn(ctx, workerAuth.GetKeyId(), scope.Global.String(), rw, rw, kmsCache))

	// now we pull the auth back from the db, decrypt it with the new key, and ensure things match
	got := allocWorkerAuth()
	got.WorkerKeyIdentifier = workerAuth.WorkerKeyIdentifier
	assert.NoError(t, rw.LookupById(ctx, got))

	kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), worker.GetScopeId(), kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
	assert.NoError(t, err)
	newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
	assert.NoError(t, err)

	// decrypt with the new key version and check to make sure things match
	decryptedGotPrivKey, err := decrypt(ctx, got.ControllerEncryptionPrivKey, kmsWrapper2)
	assert.NoError(t, err)
	assert.NotEmpty(t, got.GetKeyId())
	assert.NotEqual(t, workerAuth.GetKeyId(), got.GetKeyId())
	assert.Equal(t, newKeyVersionId, got.GetKeyId())
	assert.NotEqual(t, workerAuth.GetControllerEncryptionPrivKey(), got.GetControllerEncryptionPrivKey())
	assert.Equal(t, controllerEncryptionPrivKey, decryptedGotPrivKey)
}
