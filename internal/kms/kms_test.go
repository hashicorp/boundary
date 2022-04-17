package kms

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

func TestKms_KeyId(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	extWrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw)
	require.NoError(err)

	// Make the global scope base keys
	_, err = DeprecatedCreateKeysTx(ctx, rw, rw, extWrapper, rand.Reader, scope.Global.String())
	require.NoError(err)

	// Get the global scope's root wrapper
	kmsCache, err := NewKms(repo)
	require.NoError(err)
	require.NoError(kmsCache.AddExternalWrappers(ctx, WithRootWrapper(extWrapper)))
	globalRootWrapper, _, err := kmsCache.loadRoot(ctx, scope.Global.String())
	require.NoError(err)

	dks, err := repo.ListDatabaseKeys(ctx)
	require.NoError(err)
	require.Len(dks, 1)

	// Create another key version
	newKeyBytes, err := uuid.GenerateRandomBytes(32)
	require.NoError(err)
	_, err = repo.CreateDatabaseKeyVersion(ctx, globalRootWrapper, dks[0].GetPrivateId(), newKeyBytes)
	require.NoError(err)

	dkvs, err := repo.ListDatabaseKeyVersions(ctx, globalRootWrapper, dks[0].GetPrivateId())
	require.NoError(err)
	require.Len(dkvs, 2)

	keyId1 := dkvs[0].GetPrivateId()
	keyId2 := dkvs[1].GetPrivateId()

	// First test: just getting the key should return the latest
	wrapper, err := kmsCache.GetWrapper(ctx, scope.Global.String(), KeyPurposeDatabase)
	require.NoError(err)
	tKeyId, err := wrapper.KeyId(context.Background())
	require.NoError(err)
	require.Equal(keyId2, tKeyId)

	// Second: ask for each in turn
	wrapper, err = kmsCache.GetWrapper(ctx, scope.Global.String(), KeyPurposeDatabase, WithKeyId(keyId1))
	require.NoError(err)
	tKeyId, err = wrapper.KeyId(context.Background())
	require.NoError(err)
	require.Equal(keyId1, tKeyId)
	wrapper, err = kmsCache.GetWrapper(ctx, scope.Global.String(), KeyPurposeDatabase, WithKeyId(keyId2))
	require.NoError(err)
	tKeyId, err = wrapper.KeyId(context.Background())
	require.NoError(err)
	require.Equal(keyId2, tKeyId)

	// Last: verify something bogus finds nothing
	_, err = kmsCache.GetWrapper(ctx, scope.Global.String(), KeyPurposeDatabase, WithKeyId("foo"))
	require.Error(err)
}
