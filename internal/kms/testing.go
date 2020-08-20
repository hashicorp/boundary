package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func TestRootKey(t *testing.T, conn *gorm.DB, scopeId string) *RootKey {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	require.NoError(conn.Where("scope_id = ?", scopeId).Delete(AllocRootKey()).Error)
	k, err := NewRootKey(scopeId)
	require.NoError(err)
	id, err := newRootKeyId()
	require.NoError(err)
	k.PrivateId = id
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestRootKeyVersion(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, rootId string, key []byte) *RootKeyVersion {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	k, err := NewRootKeyVersion(rootId, key)
	require.NoError(err)
	id, err := newRootKeyVersionId()
	require.NoError(err)
	k.PrivateId = id
	err = k.Encrypt(context.Background(), wrapper)
	require.NoError(err)
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestKms(t *testing.T, conn *gorm.DB, rootWrapper wrapping.Wrapper) *Kms {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	kmsRepo, err := NewRepository(rw, rw)
	require.NoError(err)
	kms, err := NewKms(kmsRepo)
	require.NoError(err)
	err = kms.AddExternalWrappers(WithRootWrapper(rootWrapper))
	require.NoError(err)
	return kms
}
