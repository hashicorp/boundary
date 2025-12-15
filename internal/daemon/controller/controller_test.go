// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	boundary_plugin_assets "github.com/hashicorp/boundary/plugins/boundary"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestController_New(t *testing.T) {
	t.Run("ReconcileKeys", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		testCtx := context.Background()
		ctx, cancel := context.WithCancel(context.Background())
		tc := &TestController{
			t:              t,
			ctx:            ctx,
			cancel:         cancel,
			opts:           nil,
			shutdownDoneCh: make(chan struct{}),
			shutdownOnce:   new(sync.Once),
		}

		// TestControllerConfig(...) will create initial scopes
		conf := TestControllerConfig(t, ctx, tc, nil)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conf.Server.Database, conf.RootKms))

		// this tests a scenario where there is an audit DEK
		_, err := New(testCtx, conf)
		require.NoError(err)

		verifyFn := func() {
			// verify audit DEKs
			kmsCache := kms.TestKms(t, conf.Server.Database, conf.RootKms)
			w, err := kmsCache.GetWrapper(testCtx, scope.Global.String(), kms.KeyPurposeAudit)
			require.NoError(err)
			assert.NotNil(w)
			w, err = kmsCache.GetWrapper(testCtx, scope.Global.String(), kms.KeyPurposeOidc)
			require.NoError(err)
			assert.NotNil(w)
			w, err = kmsCache.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeOidc)
			require.NoError(err)
			assert.NotNil(w)
		}

		verifyFn()

		// this tests a scenario where there is NOT an audit DEK
		kms.TestKmsDeleteKeyPurpose(t, conf.Database, kms.KeyPurposeAudit)
		kms.TestKmsDeleteKeyPurpose(t, conf.Database, kms.KeyPurposeOidc)

		// re-init an empty cache and assert that the DEKs are not there.
		kmsCache := kms.TestKms(t, conf.Server.Database, conf.RootKms)
		w, err := kmsCache.GetWrapper(testCtx, scope.Global.String(), kms.KeyPurposeAudit)
		require.Error(err)
		assert.Nil(w)
		w, err = kmsCache.GetWrapper(testCtx, scope.Global.String(), kms.KeyPurposeOidc)
		require.Error(err)
		assert.Nil(w)
		w, err = kmsCache.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeOidc)
		require.Error(err)
		assert.Nil(w)

		// New(...) will reconcile the keys
		_, err = New(testCtx, conf)
		require.NoError(err)

		// verify audit DEKs
		verifyFn()
	})
}

func TestControllerNewListenerConfig(t *testing.T) {
	tests := []struct {
		name       string
		listeners  []*base.ServerListener
		assertions func(t *testing.T, c *Controller)
		expErr     bool
		expErrMsg  string
	}{
		{
			name: "valid listener configuration",
			listeners: []*base.ServerListener{
				{
					Config: &listenerutil.ListenerConfig{
						Purpose: []string{"api"},
					},
				},
				{
					Config: &listenerutil.ListenerConfig{
						Purpose: []string{"api"},
					},
				},
				{
					Config: &listenerutil.ListenerConfig{
						Purpose: []string{"cluster"},
					},
				},
			},
			assertions: func(t *testing.T, c *Controller) {
				require.Len(t, c.apiListeners, 2)
				require.NotNil(t, c.clusterListener)
			},
		},
		{
			name:      "listeners are required",
			listeners: []*base.ServerListener{},
			expErr:    true,
			expErrMsg: "no api listeners found",
		},
		{
			name:      "listeners are required - not nil",
			listeners: []*base.ServerListener{nil, nil},
			expErr:    true,
			expErrMsg: "no api listeners found",
		},
		{
			name:      "listeners are required - with config",
			listeners: []*base.ServerListener{{}, {}},
			expErr:    true,
			expErrMsg: "no api listeners found",
		},
		{
			name: "listeners are required - with purposes",
			listeners: []*base.ServerListener{
				{
					Config: &listenerutil.ListenerConfig{Purpose: nil},
				},
				{
					Config: &listenerutil.ListenerConfig{Purpose: nil},
				},
			},
			expErr:    true,
			expErrMsg: "no api listeners found",
		},
		{
			name: "both api and cluster listeners are required",
			listeners: []*base.ServerListener{
				{
					Config: &listenerutil.ListenerConfig{
						Purpose: []string{"api"},
					},
				},
			},
			expErr:    true,
			expErrMsg: "exactly one cluster listener is required",
		},
		{
			name: "both api and cluster listeners are required 2",
			listeners: []*base.ServerListener{
				{
					Config: &listenerutil.ListenerConfig{
						Purpose: []string{"cluster"},
					},
				},
			},
			expErr:    true,
			expErrMsg: "no api listeners found",
		},
		{
			name: "only one cluster listener is allowed",
			listeners: []*base.ServerListener{
				{
					Config: &listenerutil.ListenerConfig{
						Purpose: []string{"api"},
					},
				},
				{
					Config: &listenerutil.ListenerConfig{
						Purpose: []string{"cluster"},
					},
				},
				{
					Config: &listenerutil.ListenerConfig{
						Purpose: []string{"cluster"},
					},
				},
			},
			expErr:    true,
			expErrMsg: "exactly one cluster listener is required",
		},
		{
			name: "only one purpose is allowed per listener",
			listeners: []*base.ServerListener{
				{
					Config: &listenerutil.ListenerConfig{
						Purpose: []string{"api", "cluster"},
					},
				},
			},
			expErr:    true,
			expErrMsg: `found listener with multiple purposes "api,cluster"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			tc := &TestController{
				t:              t,
				ctx:            ctx,
				cancel:         cancel,
				opts:           nil,
				shutdownDoneCh: make(chan struct{}),
				shutdownOnce:   new(sync.Once),
			}
			conf := TestControllerConfig(t, ctx, tc, nil)
			conf.Listeners = tt.listeners

			c, err := New(ctx, conf)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			tt.assertions(t, c)
		})
	}
}

func TestController_NewPluginsConfig(t *testing.T) {
	require := require.New(t)
	testCtx := context.Background()
	ctx, cancel := context.WithCancel(context.Background())
	tc := &TestController{
		t:              t,
		ctx:            ctx,
		cancel:         cancel,
		opts:           nil,
		shutdownDoneCh: make(chan struct{}),
		shutdownOnce:   new(sync.Once),
	}

	initialConfig, err := config.DevController()
	require.NoError(err)
	tmpDir := t.TempDir()
	initialConfig.Plugins.ExecutionDir = tmpDir
	conf := TestControllerConfig(t, ctx, tc, &TestControllerOpts{Config: initialConfig})
	conf.EnabledPlugins = []base.EnabledPlugin{
		base.EnabledPluginAws,
		base.EnabledPluginHostAzure,
		base.EnabledPluginGCP,
	}

	_, err = New(testCtx, conf)
	require.NoError(err)

	// Check that both plugins were written to the temp dir
	files, err := os.ReadDir(tmpDir)
	require.NoError(err)
	require.Len(files, 3)
	for _, file := range files {
		name := filepath.Base(file.Name())
		// Remove random chars and hyphen
		name = name[0 : len(name)-6]
		switch name {
		case boundary_plugin_assets.PluginPrefix + "aws",
			boundary_plugin_assets.PluginPrefix + "azure",
			boundary_plugin_assets.PluginPrefix + "gcp":
		default:
			require.Fail("unexpected name", name)
		}
	}
}

func Test_ControllerStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	tc := &TestController{
		t:              t,
		ctx:            ctx,
		cancel:         cancel,
		opts:           nil,
		shutdownDoneCh: make(chan struct{}),
		shutdownOnce:   new(sync.Once),
	}
	conf := TestControllerConfig(t, ctx, tc, nil)

	c, err := New(ctx, conf)
	require.NoError(t, err)
	err = c.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, c.Shutdown())
	})

	sqlDb, err := tc.DbConn().SqlDB(ctx)
	require.NoError(t, err)
	rows, err := sqlDb.QueryContext(ctx, "select name from job")
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, rows.Close())
	})
	var jobNames []string
	for rows.Next() {
		var jobName string
		err := rows.Scan(&jobName)
		require.NoError(t, err)
		jobNames = append(jobNames, jobName)
	}
	require.NoError(t, rows.Err())
	// Check that the monitor job and at least one of the rewrapping jobs has been registered
	assert.Contains(t, jobNames, "data-key-version-destruction-monitor-job")
	assert.Contains(t, jobNames, "session-rewrapping-job")
}
