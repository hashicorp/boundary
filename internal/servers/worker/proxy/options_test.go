package proxy

import (
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/stretchr/testify/assert"
)

type cred struct {
	id     string
	secret string
}

func (c cred) GetPublicId() string           { return c.id }
func (c cred) Secret() credential.SecretData { return c.secret }

func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("WithEgressCredentials", func(t *testing.T) {
		assert := assert.New(t)
		c := cred{id: "test", secret: "hello"}
		opts := GetOpts(WithEgressCredentials([]credential.Credential{c}))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.WithEgressCredentials = []credential.Credential{c}
		assert.Equal(opts, testOpts)
	})
}
