package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Utils(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()
	t.Run("nothing", func(t *testing.T) {

	})
}
