package static

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestCredentialStore(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	cs := TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), WithName("my-name"), WithDescription("my-description"))
	require.NotNil(cs)
	assert.NotEmpty(cs.GetPublicId())
	assert.Equal(cs.Name, "my-name")
	assert.Equal(cs.Description, "my-description")
}

func Test_TestCredentialStores(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	count := 4
	css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), count)
	assert.Len(css, count)
}
