package static

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestCatalogs(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(proj)
	assert.NotEmpty(proj.GetPublicId())

	count := 4
	cs := TestCatalogs(t, conn, proj.GetPublicId(), count)
	assert.Len(cs, count)
	for _, c := range cs {
		assert.NotEmpty(c.GetPublicId())
	}
}
