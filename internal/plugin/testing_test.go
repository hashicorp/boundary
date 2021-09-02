package plugin

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_testPlugin(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")

	plg := testPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())
}
