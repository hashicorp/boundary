package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	aead "github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/require"
)

func TestRootKey(t *testing.T, conn *db.DB, scopeId string) *RootKey {
	t.Helper()
	require := require.New(t)
	db.TestDeleteWhere(t, conn, func() interface{} { i := AllocRootKey(); return &i }(), "scope_id = ?", scopeId)
	rw := db.New(conn)
	k, err := NewRootKey(scopeId)
	require.NoError(err)
	id, err := newRootKeyId()
	require.NoError(err)
	k.PrivateId = id
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestRootKeyVersion(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper, rootId string) (kv *RootKeyVersion, kvWrapper wrapping.Wrapper) {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	rootKeyVersionWrapper := db.TestWrapper(t)
	key, err := rootKeyVersionWrapper.(*aead.Wrapper).KeyBytes(context.Background())
	require.NoError(err)
	k, err := NewRootKeyVersion(rootId, key)
	require.NoError(err)
	id, err := newRootKeyVersionId()
	require.NoError(err)
	k.PrivateId = id
	err = k.Encrypt(context.Background(), wrapper)
	require.NoError(err)
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	_, err = rootKeyVersionWrapper.(*aead.Wrapper).SetConfig(context.Background(), wrapping.WithKeyId(k.GetPrivateId()))
	require.NoError(err)
	return k, rootKeyVersionWrapper
}

func TestKms(t *testing.T, conn *db.DB, rootWrapper wrapping.Wrapper) *Kms {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	kmsRepo, err := NewRepository(rw, rw)
	require.NoError(err)
	kms, err := NewKms(kmsRepo)
	require.NoError(err)
	err = kms.AddExternalWrappers(context.Background(), WithRootWrapper(rootWrapper))
	require.NoError(err)
	return kms
}

func TestDatabaseKey(t *testing.T, conn *db.DB, rootKeyId string) *DatabaseKey {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	db.TestDeleteWhere(t, conn, func() interface{} { i := AllocDatabaseKey(); return &i }(), "root_key_id = ?", rootKeyId)
	k, err := NewDatabaseKey(rootKeyId)
	require.NoError(err)
	id, err := newDatabaseKeyId()
	require.NoError(err)
	k.PrivateId = id
	k.RootKeyId = rootKeyId
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestDatabaseKeyVersion(t *testing.T, conn *db.DB, rootKeyVersionWrapper wrapping.Wrapper, databaseKeyId string, key []byte) *DatabaseKeyVersion {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	rootKeyId, err := rootKeyVersionWrapper.KeyId(context.Background())
	require.NoError(err)
	rootKeyVersionId := rootKeyId
	require.NotEmpty(rootKeyVersionId)
	k, err := NewDatabaseKeyVersion(databaseKeyId, key, rootKeyVersionId)
	require.NoError(err)
	id, err := newDatabaseKeyVersionId()
	require.NoError(err)
	k.PrivateId = id
	err = k.Encrypt(context.Background(), rootKeyVersionWrapper)
	require.NoError(err)
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestOplogKey(t *testing.T, conn *db.DB, rootKeyId string) *OplogKey {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	db.TestDeleteWhere(t, conn, func() interface{} { i := AllocOplogKey(); return &i }(), "root_key_id = ?", rootKeyId)
	k, err := NewOplogKey(rootKeyId)
	require.NoError(err)
	id, err := newOplogKeyId()
	require.NoError(err)
	k.PrivateId = id
	k.RootKeyId = rootKeyId
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestOplogKeyVersion(t *testing.T, conn *db.DB, rootKeyVersionWrapper wrapping.Wrapper, oplogKeyId string, key []byte) *OplogKeyVersion {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	rootKeyId, err := rootKeyVersionWrapper.KeyId(context.Background())
	require.NoError(err)
	rootKeyVersionId := rootKeyId
	require.NotEmpty(rootKeyVersionId)
	k, err := NewOplogKeyVersion(oplogKeyId, key, rootKeyVersionId)
	require.NoError(err)
	id, err := newOplogKeyVersionId()
	require.NoError(err)
	k.PrivateId = id
	err = k.Encrypt(context.Background(), rootKeyVersionWrapper)
	require.NoError(err)
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestTokenKey(t *testing.T, conn *db.DB, rootKeyId string) *TokenKey {
	t.Helper()
	require := require.New(t)
	db.TestDeleteWhere(t, conn, func() interface{} { i := AllocTokenKey(); return &i }(), "root_key_id = ?", rootKeyId)
	rw := db.New(conn)
	k, err := NewTokenKey(rootKeyId)
	require.NoError(err)
	id, err := newTokenKeyId()
	require.NoError(err)
	k.PrivateId = id
	k.RootKeyId = rootKeyId
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestTokenKeyVersion(t *testing.T, conn *db.DB, rootKeyVersionWrapper wrapping.Wrapper, tokenKeyId string, key []byte) *TokenKeyVersion {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	rootKeyId, err := rootKeyVersionWrapper.KeyId(context.Background())
	require.NoError(err)
	rootKeyVersionId := rootKeyId
	require.NotEmpty(rootKeyVersionId)
	k, err := NewTokenKeyVersion(tokenKeyId, key, rootKeyVersionId)
	require.NoError(err)
	id, err := newTokenKeyVersionId()
	require.NoError(err)
	k.PrivateId = id
	err = k.Encrypt(context.Background(), rootKeyVersionWrapper)
	require.NoError(err)
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestSessionKey(t *testing.T, conn *db.DB, rootKeyId string) *SessionKey {
	t.Helper()
	require := require.New(t)
	db.TestDeleteWhere(t, conn, func() interface{} { i := AllocSessionKey(); return &i }(), "root_key_id = ?", rootKeyId)
	rw := db.New(conn)
	k, err := NewSessionKey(rootKeyId)
	require.NoError(err)
	id, err := newSessionKeyId()
	require.NoError(err)
	k.PrivateId = id
	k.RootKeyId = rootKeyId
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestSessionKeyVersion(t *testing.T, conn *db.DB, rootKeyVersionWrapper wrapping.Wrapper, sessionKeyId string, key []byte) *SessionKeyVersion {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	rootKeyId, err := rootKeyVersionWrapper.KeyId(context.Background())
	require.NoError(err)
	rootKeyVersionId := rootKeyId
	require.NotEmpty(rootKeyVersionId)
	k, err := NewSessionKeyVersion(sessionKeyId, key, rootKeyVersionId)
	require.NoError(err)
	id, err := newSessionKeyVersionId()
	require.NoError(err)
	k.PrivateId = id
	err = k.Encrypt(context.Background(), rootKeyVersionWrapper)
	require.NoError(err)
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestOidcKey(t *testing.T, conn *db.DB, rootKeyId string) *OidcKey {
	t.Helper()
	require := require.New(t)
	db.TestDeleteWhere(t, conn, func() interface{} { i := AllocOidcKey(); return &i }(), "root_key_id = ?", rootKeyId)
	rw := db.New(conn)
	k, err := NewOidcKey(rootKeyId)
	require.NoError(err)
	id, err := newOidcKeyId()
	require.NoError(err)
	k.PrivateId = id
	k.RootKeyId = rootKeyId
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestOidcKeyVersion(t *testing.T, conn *db.DB, rootKeyVersionWrapper wrapping.Wrapper, oidcKeyId string, key []byte) *OidcKeyVersion {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	rootKeyId, err := rootKeyVersionWrapper.KeyId(context.Background())
	require.NoError(err)
	rootKeyVersionId := rootKeyId
	require.NotEmpty(rootKeyVersionId)
	k, err := NewOidcKeyVersion(oidcKeyId, key, rootKeyVersionId)
	require.NoError(err)
	id, err := newOidcKeyVersionId()
	require.NoError(err)
	k.PrivateId = id
	err = k.Encrypt(context.Background(), rootKeyVersionWrapper)
	require.NoError(err)
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestAuditKey(t *testing.T, conn *db.DB, rootKeyId string) *AuditKey {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	db.TestDeleteWhere(t, conn, func() interface{} { i := AllocAuditKey(); return &i }(), "root_key_id = ?", rootKeyId)
	rw := db.New(conn)
	k, err := NewAuditKey(ctx, rootKeyId)
	require.NoError(err)
	id, err := newAuditKeyId(ctx)
	require.NoError(err)
	k.PrivateId = id
	k.RootKeyId = rootKeyId
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}

func TestAuditKeyVersion(t *testing.T, conn *db.DB, rootKeyVersionWrapper wrapping.Wrapper, auditKeyId string, key []byte) *AuditKeyVersion {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)
	rootKeyVersionId, err := rootKeyVersionWrapper.KeyId(ctx)
	require.NoError(err)
	require.NotEmpty(rootKeyVersionId)
	k, err := NewAuditKeyVersion(ctx, auditKeyId, key, rootKeyVersionId)
	require.NoError(err)
	id, err := newAuditKeyVersionId(ctx)
	require.NoError(err)
	k.PrivateId = id
	err = k.Encrypt(context.Background(), rootKeyVersionWrapper)
	require.NoError(err)
	err = rw.Create(context.Background(), k)
	require.NoError(err)
	return k
}
