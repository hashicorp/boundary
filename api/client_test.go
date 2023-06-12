// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigSetAddress(t *testing.T) {
	type test struct {
		name       string
		input      string
		address    string
		socketAddr string
	}

	tests := []test{
		{
			name:    "bare",
			input:   "http://127.0.0.1:9200",
			address: "http://127.0.0.1:9200",
		},
		{
			name:    "bare with version",
			input:   "http://127.0.0.1:9200/v1",
			address: "http://127.0.0.1:9200",
		},
		{
			name:    "bare with version and trailing slash",
			input:   "http://127.0.0.1:9200/v1/",
			address: "http://127.0.0.1:9200",
		},
		{
			name:    "valid top level scope",
			input:   "http://127.0.0.1:9200/v1/scopes",
			address: "http://127.0.0.1:9200",
		},
		{
			name:    "valid scope",
			input:   "http://127.0.0.1:9200/v1/scopes/scopeid",
			address: "http://127.0.0.1:9200",
		},
		{
			name:    "longer path project",
			input:   "http://127.0.0.1:9200/v1/auth-methods",
			address: "http://127.0.0.1:9200",
		},
		{
			name:    "valid project",
			input:   "http://127.0.0.1:9200/my-install",
			address: "http://127.0.0.1:9200/my-install",
		},
		{
			name:    "valid project path containing v1",
			input:   "http://127.0.0.1:9200/randomPathHasv1InIt",
			address: "http://127.0.0.1:9200/randomPathHasv1InIt",
		},
		{
			name:       "unix socket with linux pathing",
			input:      "unix:///home/username/.boundary/socketdir/boundary.sock",
			address:    "unix:///home/username/.boundary/socketdir/boundary.sock",
			socketAddr: "/home/username/.boundary/socketdir/boundary.sock",
		},
		{
			name:       "unix socket with weird linux pathing",
			input:      "unix:///home/username/.boundary/something/../socketdir/boundary.sock",
			address:    "unix:///home/username/.boundary/socketdir/boundary.sock",
			socketAddr: "/home/username/.boundary/socketdir/boundary.sock",
		},
		{
			name:       "unix socket with windows pathing",
			input:      "unix://C:\\Users\\Admin\\AppData\\boundary.sock",
			address:    "unix://C:\\Users\\Admin\\AppData\\boundary.sock",
			socketAddr: "C:\\Users\\Admin\\AppData\\boundary.sock",
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			var c Config
			err := c.setAddr(v.input)
			assert.NoError(t, err)
			assert.Equal(t, v.address, c.Addr)
			assert.Equal(t, v.socketAddr, c.socketAddr)
		})
	}
}
