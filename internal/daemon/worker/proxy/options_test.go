// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"net"
	"reflect"
	"runtime"
	"testing"

	serverpb "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("WithInjectedApplicationCredentials", func(t *testing.T) {
		assert := assert.New(t)
		c := &serverpb.Credential{
			Credential: &serverpb.Credential_UsernamePassword{
				UsernamePassword: &serverpb.UsernamePassword{
					Username: "user",
					Password: "pass",
				},
			},
		}
		opts := GetOpts(WithInjectedApplicationCredentials([]*serverpb.Credential{c}))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.WithInjectedApplicationCredentials = []*serverpb.Credential{c}
		assert.Equal(opts, testOpts)
	})

	t.Run("WithPostConnectionHook", func(t *testing.T) {
		assert := assert.New(t)
		testFn := func(net.Conn) {}
		opts := GetOpts(WithPostConnectionHook(testFn))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.WithPostConnectionHook = testFn
		assert.Equal(
			runtime.FuncForPC(reflect.ValueOf(opts.WithPostConnectionHook).Pointer()).Name(),
			runtime.FuncForPC(reflect.ValueOf(testOpts.WithPostConnectionHook).Pointer()).Name(),
		)
	})
}
