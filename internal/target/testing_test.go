package target

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestTcpTarget(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	name := testTargetName(t, org.PublicId)
	target := TestTcpTarget(t, conn, org.PublicId, name)
	require.NotNil(t)
	assert.NotEmpty(target.PublicId)
	assert.Equal(name, target.Name)
}
