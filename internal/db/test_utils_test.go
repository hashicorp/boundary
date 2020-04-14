package db

import (
	"testing"

	"gotest.tools/assert"
)

func Test_All(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		StartTest()
		t.Parallel()
		cleanup, url := SetupTest(t, "migrations/postgres")
		defer cleanup()
		defer CompleteTest() // must come after the "defer cleanup()"
		db, err := TestConnection(url)
		assert.NilError(t, err)
		defer db.Close()
	})
}
