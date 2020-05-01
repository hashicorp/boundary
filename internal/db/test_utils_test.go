package db

import (
	"testing"
)

func Test_Utils(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, conn := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	defer conn.Close()
	t.Run("nothing", func(t *testing.T) {

	})
}
