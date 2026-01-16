// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_openStore(t *testing.T) {
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := openStore(ctx, WithUrl(ctx, tmpDir+"/test.db"+fkPragma))
		require.NoError(t, err)
		require.NotNil(t, store)
		assert.FileExists(t, tmpDir+"/test.db")
		rw := db.New(store)
		rows, err := rw.Query(ctx, "select * from target", nil)
		require.NoError(t, err)
		rows.Close()
	})
	t.Run("homedir", func(t *testing.T) {
		tmpDir := t.TempDir()
		db, err := openStore(ctx, WithHomeDir(ctx, tmpDir))
		require.NoError(t, err)
		require.NotNil(t, db)
		assert.FileExists(t, tmpDir+"/"+dotDirname+"/"+dbFileName)
	})
	t.Run("log-level-debug", func(t *testing.T) {
		buf := new(strings.Builder)
		testLock := &sync.Mutex{}
		testLogger := hclog.New(&hclog.LoggerOptions{
			Mutex:      testLock,
			Name:       "test",
			JSONFormat: true,
			Output:     buf,
			Level:      hclog.Debug,
		})
		tmpDir := t.TempDir()
		store, err := openStore(ctx,
			WithUrl(ctx, tmpDir+"/test.db"+fkPragma),
			WithLogger(ctx, testLogger),
		)
		require.NoError(t, err)
		require.NotNil(t, store)
		assert.FileExists(t, tmpDir+"/test.db")
		rw := db.New(store)

		rows, err := rw.Query(ctx, "select * from target", nil)
		require.NoError(t, err)
		defer rows.Close()
		assert.Contains(t, buf.String(), "select * from target")
		t.Log(buf.String())
	})
}

// Note: the name of this test must remain short because the temp dir created
// includes the name of the test and there is a 108 character limit in allowed
// unix socket path names.
func TestDefaultBoundaryTokenReader(t *testing.T) {
	ctx := context.Background()

	t.Run("nil client provider", func(t *testing.T) {
		resFn, err := defaultBoundaryTokenReader(ctx, nil)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "client provider is nil")
		assert.Nil(t, resFn)
	})

	tc := controller.NewTestController(t, nil)
	client := tc.Client()
	client.SetToken(tc.Token().Token)
	rclient := roles.NewClient(client)
	rl, err := rclient.List(ctx, "global", roles.WithRecursive(true))
	require.NoError(t, err)

	// delete everything except for the admin role
	for _, r := range rl.Items {
		if r.Name == "Administration" {
			continue
		}
		_, err := rclient.Delete(ctx, r.Id)
		require.NoError(t, err)
	}

	cp := fakeClientProvider{tc}

	cases := []struct {
		name        string
		address     string
		token       string
		errContains string
	}{
		{
			name:        "success",
			address:     tc.ApiAddrs()[0],
			token:       tc.Token().Token,
			errContains: "",
		},
		{
			name:        "token cant read itself",
			address:     tc.ApiAddrs()[0],
			token:       tc.UnprivilegedToken().Token,
			errContains: "PermissionDenied",
		},
		{
			name:        "empty address",
			address:     "",
			token:       "at_123_testtoken",
			errContains: "address is missing",
		},
		{
			name:        "empty token",
			address:     tc.ApiAddrs()[0],
			token:       "",
			errContains: "auth token is missing",
		},
		{
			name:        "malformed token to many sections",
			address:     tc.ApiAddrs()[0],
			token:       "at_123_ignoredtoken_tomanysections",
			errContains: "auth token is malformed",
		},
		{
			name:        "malformed token to few sections",
			address:     tc.ApiAddrs()[0],
			token:       "at_123",
			errContains: "auth token is malformed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			retFn, err := defaultBoundaryTokenReader(ctx, cp)
			require.NoError(t, err)
			require.NotNil(t, retFn)

			at, err := retFn(ctx, tc.address, tc.token)
			switch tc.errContains {
			case "":
				assert.NoError(t, err)
				assert.NotNil(t, at)
			default:
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.errContains)
				assert.Nil(t, at)
			}
		})
	}
}

type fakeClientProvider struct {
	*controller.TestController
}

func (fcp fakeClientProvider) Client(opt ...base.Option) (*api.Client, error) {
	return fcp.TestController.Client(), nil
}
