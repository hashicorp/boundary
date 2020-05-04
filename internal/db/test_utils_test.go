package db

import (
	"testing"
)

func Test_Utils(t *testing.T) {
	t.Parallel()
	cleanup, conn := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer conn.Close()
	t.Run("nothing", func(t *testing.T) {

	})
}
