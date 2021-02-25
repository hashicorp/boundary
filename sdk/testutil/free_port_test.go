package testutil

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestFreePort(t *testing.T) {
	t.Parallel()
	t.Run("simple-validation", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		p := TestFreePort(t)
		assert.NotEmpty(p)

		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("localhost:%d", p))
		require.NoError(err)
		l, err := net.ListenTCP("tcp", addr)
		require.NoError(err)
		defer l.Close()
	})
}
