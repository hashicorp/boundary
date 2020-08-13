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
	extConf := TestExternalConfig(t, conn, wrapper, org.PublicId, DevKms, "{}")
	require.NotNil(extConf)
	assert.Equal(DevKms.String(), extConf.Type)
	assert.Equal("{}", extConf.Config)
	assert.NotEmpty(extConf.PrivateId)
}
