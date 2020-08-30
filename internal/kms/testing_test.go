package kms_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestRootKey(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	k := kms.TestRootKey(t, conn, org.PublicId)
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)
}

func Test_TestRootKeyVersion(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	rk := kms.TestRootKey(t, conn, org.PublicId)
	k := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId, []byte("test key"))
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)
}

func Test_TestDatabaseKey(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	k := kms.TestRootKey(t, conn, org.PublicId)
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)

	dk := kms.TestDatabaseKey(t, conn, k.PrivateId)
	require.NotNil(dk)
	assert.NotEmpty(dk.PrivateId)
}

func Test_TestDatabaseKeyVersion(t *testing.T) {
	t.Helper()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsWrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, kmsWrapper))
	require.NoError(conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	rk := kms.TestRootKey(t, conn, org.PublicId)
	rootKeyVersionWrapper := db.TestWrapper(t)
	key := rootKeyVersionWrapper.(*aead.Wrapper).GetKeyBytes()
	kv := kms.TestRootKeyVersion(t, conn, kmsWrapper, rk.PrivateId, key)
	_, err := rootKeyVersionWrapper.(*aead.Wrapper).SetConfig(map[string]string{
		"key_id": kv.GetPrivateId(),
	})
	require.NoError(err)
	dk := kms.TestDatabaseKey(t, conn, rk.PrivateId)
	dv := kms.TestDatabaseKeyVersion(t, conn, rootKeyVersionWrapper, dk.PrivateId, []byte("test dek key"))
	require.NotNil(dv)
	require.NotEmpty(dv.PrivateId)
}
