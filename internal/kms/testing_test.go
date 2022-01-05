package kms_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestRootKey(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	k := kms.TestRootKey(t, conn, org.PublicId)
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)
}

func Test_TestRootKeyVersion(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	k, _ := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)
}

func Test_TestDatabaseKey(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	k := kms.TestRootKey(t, conn, org.PublicId)
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)

	dk := kms.TestDatabaseKey(t, conn, k.PrivateId)
	require.NotNil(dk)
	assert.NotEmpty(dk.PrivateId)
}

func Test_TestDatabaseKeyVersion(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsWrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, kmsWrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rootKeyVersionWrapper := kms.TestRootKeyVersion(t, conn, kmsWrapper, rk.PrivateId)
	dk := kms.TestDatabaseKey(t, conn, rk.PrivateId)
	dv := kms.TestDatabaseKeyVersion(t, conn, rootKeyVersionWrapper, dk.PrivateId, []byte("test dek key"))
	require.NotNil(dv)
	require.NotEmpty(dv.PrivateId)
}

func Test_TestOplogKey(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	k := kms.TestRootKey(t, conn, org.PublicId)
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)

	opk := kms.TestOplogKey(t, conn, k.PrivateId)
	require.NotNil(opk)
	assert.NotEmpty(opk.PrivateId)
}

func Test_TestOplogKeyVersion(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsWrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, kmsWrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rootKeyVersionWrapper := kms.TestRootKeyVersion(t, conn, kmsWrapper, rk.PrivateId)
	opk := kms.TestOplogKey(t, conn, rk.PrivateId)
	opv := kms.TestOplogKeyVersion(t, conn, rootKeyVersionWrapper, opk.PrivateId, []byte("test dek key"))
	require.NotNil(opv)
	require.NotEmpty(opv.PrivateId)
}

func Test_TestTokenKey(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	k := kms.TestRootKey(t, conn, org.PublicId)
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)

	tk := kms.TestTokenKey(t, conn, k.PrivateId)
	require.NotNil(tk)
	assert.NotEmpty(tk.PrivateId)
}

func Test_TestTokenKeyVersion(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsWrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, kmsWrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rootKeyVersionWrapper := kms.TestRootKeyVersion(t, conn, kmsWrapper, rk.PrivateId)
	tk := kms.TestTokenKey(t, conn, rk.PrivateId)
	tv := kms.TestTokenKeyVersion(t, conn, rootKeyVersionWrapper, tk.PrivateId, []byte("test dek key"))
	require.NotNil(tv)
	require.NotEmpty(tv.PrivateId)
}

func Test_TestSessionKey(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	k := kms.TestRootKey(t, conn, org.PublicId)
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)

	sk := kms.TestSessionKey(t, conn, k.PrivateId)
	require.NotNil(sk)
	assert.NotEmpty(sk.PrivateId)
}

func Test_TestSessionKeyVersion(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsWrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, kmsWrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rootKeyVersionWrapper := kms.TestRootKeyVersion(t, conn, kmsWrapper, rk.PrivateId)
	sk := kms.TestSessionKey(t, conn, rk.PrivateId)
	sv := kms.TestSessionKeyVersion(t, conn, rootKeyVersionWrapper, sk.PrivateId, []byte("test dek key"))
	require.NotNil(sv)
	require.NotEmpty(sv.PrivateId)
}
