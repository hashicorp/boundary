// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestController(t *testing.T) {
	t.Run("startup and shutdown", func(t *testing.T) {
		t.Parallel()
		tc := NewTestController(t, nil)
		defer tc.Shutdown()
	})
	t.Run("start 2 controllers", func(t *testing.T) {
		t.Parallel()
		tc1 := NewTestController(t, nil)
		tc2 := NewTestController(t, nil)
		defer tc1.Shutdown()
		defer tc2.Shutdown()
	})
	t.Run("controller-without-eventing", func(t *testing.T) {
		const op = "Test_TestWithoutEventing"
		assert := assert.New(t)

		// this isn't the best solution for capturing stdout but it works for now...
		captureFn := func(fn func()) string {
			old := os.Stdout
			defer func() {
				os.Stderr = old
			}()

			r, w, _ := os.Pipe()
			os.Stderr = w

			{
				fn()
			}

			outC := make(chan string)
			// copy the output in a separate goroutine so writing to stderr can't block indefinitely
			go func() {
				var buf bytes.Buffer
				_, _ = io.Copy(&buf, r)
				outC <- buf.String()
			}()

			// back to normal state
			w.Close()
			return <-outC
		}

		assert.Empty(captureFn(func() {
			tc := NewTestController(t, nil)
			defer tc.Shutdown()
		}))
		assert.NotEmpty(captureFn(func() {
			tc := NewTestController(t, &TestControllerOpts{EnableEventing: true})
			defer tc.Shutdown()
		}))
	})
	t.Run("set-default-ldap-auth-method-id", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		testCtx := context.Background()
		testLdapAuthMethodId := globals.LdapAuthMethodPrefix + "_0123456789"
		tc := NewTestController(t, &TestControllerOpts{DefaultLdapAuthMethodId: testLdapAuthMethodId})
		defer tc.Shutdown()

		testRw := db.New(tc.DbConn())
		testLdapRepo, err := ldap.NewRepository(testCtx, testRw, testRw, tc.c.kms)
		require.NoError(err)
		got, err := testLdapRepo.LookupAuthMethod(testCtx, testLdapAuthMethodId)
		require.NoError(err)
		assert.Equal(testLdapAuthMethodId, got.GetPublicId())
	})
	t.Run("controller-external-wrappers", func(t *testing.T) {
		testCtx := context.Background()
		assert := assert.New(t)
		tc := NewTestController(t, nil)
		defer tc.Shutdown()

		ws := tc.Kms().GetExternalWrappers(testCtx)

		assert.NotNil(ws.Root())
		assert.NotNil(ws.WorkerAuth())
		assert.NotNil(ws.Recovery())
		assert.NotNil(ws.Bsr())
	})
}

func Test_TestControllerIPv6(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	c := NewTestController(t, &TestControllerOpts{
		EnableIPv6: true,
	})
	require.NotNil(c)
	validateIPv6 := func(addr, name string) {
		host, _, err := net.SplitHostPort(addr)
		require.NoError(err)
		require.NotEmpty(host, "missing host")
		ip := net.ParseIP(host)
		assert.NotNil(ip, "failed to parse %s", name)
		assert.NotNil(ip.To16(), "%s is not IPv6 %s", name, addr)
	}
	for _, addr := range c.ClusterAddrs() {
		validateIPv6(addr, "cluster addr")
	}
	for _, addr := range c.ApiAddrs() {
		addr = strings.ReplaceAll(addr, "http://", "")
		validateIPv6(addr, "api addr")
	}
}
