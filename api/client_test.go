// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	}

	tests := []test{
		{
			"bare",
			"http://127.0.0.1:9200",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"bare with version",
			"http://127.0.0.1:9200/v1",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"bare with version and trailing slash",
			"http://127.0.0.1:9200/v1/",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"valid top level scope",
			"http://127.0.0.1:9200/v1/scopes",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"valid scope",
			"http://127.0.0.1:9200/v1/scopes/scopeid",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"longer path project",
			"http://127.0.0.1:9200/v1/auth-methods",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"valid project",
			"http://127.0.0.1:9200/my-install",
			"http://127.0.0.1:9200/my-install",
			"",
		},
		{
			"valid project path containing v1",
			"http://127.0.0.1:9200/randomPathHasv1InIt",
			"http://127.0.0.1:9200/randomPathHasv1InIt",
			"",
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
		})
	}
}
