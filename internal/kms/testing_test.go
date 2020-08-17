package kms

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestRootKey(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := iam.TestScopes(t, conn)
	k := TestRootKey(t, conn, org.PublicId)
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)
}

func Test_TestRootKeyVersion(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, conn)
	rk := TestRootKey(t, conn, org.PublicId)
	k := TestRootKeyVersion(t, conn, wrapper, rk.PrivateId, []byte("test key"))
	require.NotNil(k)
	assert.NotEmpty(k.PrivateId)
}
