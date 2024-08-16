// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestReadEnvironmentMaxRetries(t *testing.T) {
	tests := []struct {
		name           string
		inp            string
		expMaxRetries  int
		expErrContains string
	}{
		{
			name:           "invalidNaN",
			inp:            "bad",
			expErrContains: "strconv.ParseUint: parsing \"bad\": invalid syntax",
		},
		{
			name:           "invalidNegativeNumber",
			inp:            "-1",
			expErrContains: "strconv.ParseUint: parsing \"-1\": invalid syntax",
		},
		{
			name:           "invalidGreaterThanUint32",
			inp:            strconv.Itoa(math.MaxUint32 + 10),
			expErrContains: "strconv.ParseUint: parsing \"4294967305\": value out of range",
		},
		{
			name:           "invalidGreaterThanInt32",
			inp:            strconv.Itoa(math.MaxInt32 + 10),
			expErrContains: "max retries must be less than or equal to 2147483647",
		},
		{
			name:          "success1",
			inp:           "0",
			expMaxRetries: 0,
		},
		{
			name:          "success2",
			inp:           "10000",
			expMaxRetries: 10000,
		},
		{
			name:          "successMaxInt32",
			inp:           strconv.Itoa(math.MaxInt32),
			expMaxRetries: math.MaxInt32,
		},
		{
			name:          "successNothing",
			inp:           "",
			expMaxRetries: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(EnvBoundaryMaxRetries, tt.inp)
			t.Cleanup(func() { os.Unsetenv(EnvBoundaryMaxRetries) })

			var c Config
			err := c.ReadEnvironment()
			if tt.expErrContains != "" {
				require.ErrorContains(t, err, tt.expErrContains)
				require.Equal(t, 0, c.MaxRetries)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expMaxRetries, c.MaxRetries)
		})
	}
}
