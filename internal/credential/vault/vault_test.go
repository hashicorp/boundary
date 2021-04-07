package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_newClient(t *testing.T) {
	t.Parallel()
	t.Run("nilConfig", func(t *testing.T) {
		assert := assert.New(t)
		var c *clientConfig
		client, err := newClient(c)
		assert.Error(err)
		assert.Nil(client)
	})
}
