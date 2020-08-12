package kms

import (
	"strings"
	"testing"

	"github.com/alecthomas/assert"
	"github.com/stretchr/testify/require"
)

func Test_Ids(t *testing.T) {
	t.Run("kec", func(t *testing.T) {
		id, err := newExternalConfigId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, ExternalConfigPrefix+"_"))
	})
}
