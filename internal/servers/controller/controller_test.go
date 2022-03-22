package controller

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/stretchr/testify/require"
)

func TestController_New(t *testing.T) {
	t.Run("ReconcileKeys", func(t *testing.T) {
		require := require.New(t)
		testCtx := context.Background()
		ctx, cancel := context.WithCancel(context.Background())
		tc := &TestController{
			t:      t,
			ctx:    ctx,
			cancel: cancel,
			opts:   nil,
		}
		conf := TestControllerConfig(t, ctx, tc, nil)

		// this tests a scenario where there is an audit DEK
		c, err := New(testCtx, conf)
		require.NoError(err)

		// this tests a scenario where there is NOT an audit DEK
		db.TestDeleteWhere(t, c.conf.Server.Database, func() interface{} { i := kms.AllocAuditKey(); return &i }(), "1=1")
		_, err = New(testCtx, conf)
		require.NoError(err)
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
