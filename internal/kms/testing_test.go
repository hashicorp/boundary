package kms

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestExternalConfig(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, conn)
	extConf := TestExternalConfig(t, conn, wrapper, org.PublicId, AeadKms, "{}")
	require.NotNil(extConf)
	assert.Equal(AeadKms.String(), extConf.Type)
	assert.Equal("{}", extConf.Config)
	assert.NotEmpty(extConf.PrivateId)
}

func Test_TestRootKey(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := iam.TestScopes(t, conn)
	extConf := TestRootKey(t, conn, org.PublicId)
	require.NotNil(extConf)
	assert.NotEmpty(extConf.PrivateId)
}
