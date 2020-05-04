package tests

import (
	"testing"
	"time"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/hosts"
	"github.com/stretchr/testify/assert"
)

func TestDetailTemplating(t *testing.T) {
	lt := time.Now()
	c := hosts.HostCatalog{
		Path:        api.String("path"),
		CreatedTime: lt,
		Attributes: map[string]interface{}{
			"regions":    []string{"a", "b"},
			"access_key": "access",
			"secret_key": "secret",
			"rotate":     true,
		},
	}

	ac, err := c.AsAwsEc2HostCatalog()
	assert.NoError(t, err)
	assert.Equal(t, &hosts.AwsEc2HostCatalog{
		HostCatalog: &c,
		Regions:     []string{"a", "b"},
		AccessKey:   api.String("access"),
		SecretKey:   api.String("secret"),
		Rotate:      api.Bool(true),
	}, ac)
}
