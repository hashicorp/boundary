// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"crypto/ed25519"
	"io"
	"net"
	"reflect"
	"runtime"
	"strings"
	"testing"

	serverpb "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
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
	t.Run("WithTestKdcAdress", func(t *testing.T) {
		assert := assert.New(t)
		testKdcAddress := "test-kdc-address"
		opts := GetOpts(WithTestKdcAddress(testKdcAddress))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.WithTestKdcAddress = testKdcAddress
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTestKerberosServerHostname", func(t *testing.T) {
		assert := assert.New(t)
		testKerberosServerHostname := "test-kerberos-server-hostname"
		opts := GetOpts(WithTestKerberosServerHostname(testKerberosServerHostname))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.WithTestKerberosServerHostname = testKerberosServerHostname
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSshHostKeyCallback", func(t *testing.T) {
		assert := assert.New(t)
		opts := getDefaultOptions()
		assert.Nil(opts.WithSshHostKeyCallback)

		signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed([]byte("foobfoobfoobfoobfoobfoobfoobfoob")))
		assert.NoError(err)

		opts = GetOpts(WithSshHostKeyCallback(ssh.FixedHostKey(signer.PublicKey())))
		assert.NotNil(opts.WithSshHostKeyCallback)
	})
	t.Run("WithRandomReader", func(t *testing.T) {
		reader := io.Reader(&strings.Reader{})
		opts := GetOpts(WithRandomReader(reader))
		testOpts := getDefaultOptions()
		testOpts.WithRandomReader = reader
		assert.Equal(t, opts, testOpts)
	})
}
