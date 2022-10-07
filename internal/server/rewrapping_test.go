package server

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/types"
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

	currentRoot, err := workerAuthRepo.convertRootCertificate(ctx, roots.Current)
	assert.NoError(t, err)

	// now things are stored in the db, we can rotate and rewrap
	err = kmsCache.RotateKeys(ctx, scope.Global.String())
	assert.NoError(t, err)

	err = workerAuthCertRewrapFn(ctx, currentRoot.KeyId, rw, rw, kmsCache)
	assert.NoError(t, err)

	// now we pull the certs back from the db, decrypt it with the new key, and ensure things match
	newRoots := &types.RootCertificates{Id: CaId}
	err = workerAuthRepo.Load(ctx, newRoots)
	assert.NoError(t, err)
	newRoots.Current.Id = string(CurrentState)
	assert.NoError(t, err)

	// decryption occurs during Load, so we just want to make sure everything is expected
	assert.Equal(t, roots.Current.Id, newRoots.Current.Id)
	assert.Equal(t, roots.Current.PrivateKeyPkcs8, newRoots.Current.PrivateKeyPkcs8)
}
