package worker

import (
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	//"github.com/hashicorp/boundary/internal/daemon/controller"
	//"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/go-hclog"
	//wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/stretchr/testify/require"
)

func TestWorkerNew(t *testing.T) {
	tests := []struct {
		name       string
		in         *Config
		expErr     bool
		expErrMsg  string
		assertions func(t *testing.T, w *Worker)
	}{
		{
			name:      "nil listeners",
			in:        &Config{Server: &base.Server{Listeners: nil}},
			expErr:    true,
			expErrMsg: "exactly one proxy listener is required",
		},
		{
			name:      "zero listeners",
			in:        &Config{Server: &base.Server{Listeners: []*base.ServerListener{}}},
			expErr:    true,
			expErrMsg: "exactly one proxy listener is required",
		},
		{
			name: "populated with nil values",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						nil,
						{Config: nil},
						{Config: &listenerutil.ListenerConfig{Purpose: nil}},
					},
				},
			},
			expErr:    true,
			expErrMsg: "exactly one proxy listener is required",
		},
		{
			name: "multiple purposes",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						nil,
						{Config: nil},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"api", "proxy"}}},
					},
				},
			},
			expErr:    true,
			expErrMsg: `found listener with multiple purposes "api,proxy"`,
		},
		{
			name: "too many proxy listeners",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"api"}}},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"cluster"}}},
					},
				},
			},
			expErr:    true,
			expErrMsg: "exactly one proxy listener is required",
		},
		{
			name: "valid listeners",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"api"}}},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"cluster"}}},
					},
				},
			},
			expErr: false,
		},
		{
			name: "worker nonce func is set",
			in: &Config{
				Server: &base.Server{
					Listeners: []*base.ServerListener{
						{Config: &listenerutil.ListenerConfig{Purpose: []string{"proxy"}}},
					},
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker) {
				require.NotNil(t, w.nonceFn)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// New() panics if these aren't set
			tt.in.Logger = hclog.Default()
			tt.in.RawConfig = &config.Config{SharedConfig: &configutil.SharedConfig{DisableMlock: true}}

			w, err := New(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, w)
				return
			}

			require.NoError(t, err)
			if tt.assertions != nil {
				tt.assertions(t, w)
			}
		})
	}
}

//
//func TestWorkerEncryption(t *testing.T) {
//
//	encryptMsg := &wrapping.BlobInfo{
//		Ciphertext: []byte("foo"),
//		Iv:         []byte("bar"),
//		Hmac:       []byte("baz"),
//	}
//
//	tests := []struct {
//		name       string
//		in         *Config
//		expErr     bool
//		expErrMsg  string
//		assertions func(t *testing.T, w *Worker)
//	}{
//		{
//			name:      "nil listeners",
//			in:        &Config{Server: &base.Server{Listeners: nil}},
//			expErr:    true,
//			expErrMsg: "exactly one proxy listener is required",
//		},
//	}
//	for _, t = range tests {
//		conf, err := config.DevController()
//		wrapper := db.TestWrapper(t)
//		require.NoError(t, err)
//		c1 := controller.NewTestController(t, &controller.TestControllerOpts{
//			Config:                 conf,
//			InitialResourcesSuffix: "1234567890",
//			DefaultPassword:        "password",
//		})
//		defer c1.Shutdown()
//
//		ctx := c1.Context()
//		conf, err = config.DevWorker()
//		w1 := NewTestWorker(t, &TestWorkerOpts{
//			Config:             conf,
//			WorkerStorage:      c1.Config().WorkerStorage,
//			InitialControllers: c1.ApiAddrs(),
//		})
//
//	})
//}
