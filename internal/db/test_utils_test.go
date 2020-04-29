package db

import (
	"testing"

	"gotest.tools/assert"
)

func Test_Utils(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("nothing", func(t *testing.T) {

	})
}
