package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	host_plugin_assets "github.com/hashicorp/boundary/plugins/host"
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
			t:      t,
			ctx:    ctx,
			cancel: cancel,
			opts:   nil,
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
				t:      t,
				ctx:    ctx,
				cancel: cancel,
				opts:   nil,
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
		t:      t,
		ctx:    ctx,
		cancel: cancel,
		opts:   nil,
	}

	initialConfig, err := config.DevController()
	require.NoError(err)
	tmpDir := t.TempDir()
	initialConfig.Plugins.ExecutionDir = tmpDir
	conf := TestControllerConfig(t, ctx, tc, &TestControllerOpts{Config: initialConfig})
	conf.EnabledPlugins = []base.EnabledPlugin{
		base.EnabledPluginHostAws,
		base.EnabledPluginHostAzure,
	}

	_, err = New(testCtx, conf)
	require.NoError(err)

	// Check that both plugins were written to the temp dir
	files, err := os.ReadDir(tmpDir)
	require.NoError(err)
	require.Len(files, 2)
	var pluginNames []string
	for _, file := range files {
		pluginNames = append(pluginNames, filepath.Base(file.Name()))
	}
	expectedPluginNames := []string{host_plugin_assets.HostPluginPrefix + "aws.gz", host_plugin_assets.HostPluginPrefix + "azure.gz"}
	require.Empty(cmp.Diff(expectedPluginNames, pluginNames))
}
