package proxy

import (
	"testing"

	serverpb "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("WithEgressCredentials", func(t *testing.T) {
		assert := assert.New(t)
		c := &serverpb.Credential{
			Credential: &serverpb.Credential_UserPassword{
				UserPassword: &serverpb.UserPassword{
					Username: "user",
					Password: "pass",
				},
			},
		}
		opts := GetOpts(WithEgressCredentials([]*serverpb.Credential{c}))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.WithEgressCredentials = []*serverpb.Credential{c}
		assert.Equal(opts, testOpts)
	})
}
