package worker

import (
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/stretchr/testify/require"
)

func TestWorkerNewListenerConfig(t *testing.T) {
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
			expErrMsg: "no proxy listeners found",
		},
		{
			name:      "zero listeners",
			in:        &Config{Server: &base.Server{Listeners: []*base.ServerListener{}}},
			expErr:    true,
			expErrMsg: "no proxy listeners found",
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
			expErrMsg: "no proxy listeners found",
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
			name: "valid listeners",
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
			expErr: false,
			assertions: func(t *testing.T, w *Worker) {
				require.Len(t, w.listeners, 2)
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
