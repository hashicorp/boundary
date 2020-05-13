package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigSetAddress(t *testing.T) {
	type test struct {
		name    string
		input   string
		address string
		err     string
		org     string
		project string
	}

	tests := []test{
		{
			"bare",
			"http://127.0.0.1:9200",
			"http://127.0.0.1:9200",
			"",
			"",
			"",
		},
		{
			"bare with version",
			"http://127.0.0.1:9200/v1",
			"http://127.0.0.1:9200",
			"",
			"",
			"",
		},
		{
			"bare with version and trailing slash",
			"http://127.0.0.1:9200/v1/",
			"http://127.0.0.1:9200",
			"",
			"",
			"",
		},
		{
			"invalid org",
			"http://127.0.0.1:9200/v1/org",
			"http://127.0.0.1:9200",
			"unexpected number of segments in address",
			"",
			"",
		},
		{
			"valid org",
			"http://127.0.0.1:9200/v1/orgs/orgid",
			"http://127.0.0.1:9200",
			"",
			"orgid",
			"",
		},
		{
			"invalid project",
			"http://127.0.0.1:9200/v1/orgs/orgid/projects",
			"http://127.0.0.1:9200",
			"unexpected number of segments in address",
			"",
			"",
		},
		{
			"valid project",
			"http://127.0.0.1:9200/v1/orgs/orgid/projects/projid",
			"http://127.0.0.1:9200",
			"",
			"orgid",
			"projid",
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			var c Config
			err := c.setAddr(v.input)
			if err != nil {
				assert.Equal(t, v.err, err.Error())
			}
			assert.Equal(t, v.address, c.Addr)
			assert.Equal(t, v.org, c.Org)
			assert.Equal(t, v.project, c.Project)
		})
	}
}
