// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
)

func TestRepository_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)

	plgs := map[string]plgpb.HostPluginServiceClient{}

	type args struct {
		r         db.Reader
		w         db.Writer
		kms       *kms.Kms
		scheduler *scheduler.Scheduler
		plugins   map[string]plgpb.HostPluginServiceClient
		opts      []host.Option
	}

	tests := []struct {
		name      string
		args      args
		want      *Repository
		wantIsErr errors.Code
	}{
		{
			name: "valid",
			args: args{
				r:         rw,
				w:         rw,
				kms:       kmsCache,
				scheduler: sched,
				plugins:   plgs,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				scheduler:    sched,
				plugins:      plgs,
				defaultLimit: db.DefaultLimit,
			},
		},
		{
			name: "valid-with-limit",
			args: args{
				r:         rw,
				w:         rw,
				kms:       kmsCache,
				scheduler: sched,
				plugins:   plgs,
				opts:      []host.Option{host.WithLimit(5)},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				scheduler:    sched,
				plugins:      plgs,
				defaultLimit: 5,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r:         nil,
				w:         rw,
				kms:       kmsCache,
				scheduler: sched,
				plugins:   plgs,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-writer",
			args: args{
				r:         rw,
				w:         nil,
				kms:       kmsCache,
				scheduler: sched,
				plugins:   plgs,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-kms",
			args: args{
				r:         rw,
				w:         rw,
				kms:       nil,
				scheduler: sched,
				plugins:   plgs,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-plugins",
			args: args{
				r:         rw,
				w:         rw,
				kms:       kmsCache,
				scheduler: sched,
				plugins:   nil,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-scheduler",
			args: args{
				r:         rw,
				w:         rw,
				kms:       kmsCache,
				scheduler: nil,
				plugins:   plgs,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "all-nils",
			args: args{
				r:         nil,
				w:         nil,
				kms:       nil,
				scheduler: nil,
				plugins:   nil,
			},
			want:      nil,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.args.scheduler, tt.args.plugins, tt.args.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}

func TestPluginClientFactory(t *testing.T) {
	t.Run("nilHostCatalog", func(t *testing.T) {
		cl, err := pluginClientFactory(
			context.Background(),
			nil,
			map[string]plgpb.HostPluginServiceClient{},
		)
		require.ErrorContains(t, err, "host catalog object not present")
		require.Nil(t, cl)
	})

	t.Run("pluginDoesntExist", func(t *testing.T) {
		cl, err := pluginClientFactory(
			context.Background(),
			&hostcatalogs.HostCatalog{PluginId: "not_present"},
			map[string]plgpb.HostPluginServiceClient{},
		)
		require.ErrorContains(t, err, "controller plugin \"not_present\" not available")
		require.Nil(t, cl)
	})

	t.Run("pluginNilClient", func(t *testing.T) {
		cl, err := pluginClientFactory(
			context.Background(),
			&hostcatalogs.HostCatalog{PluginId: "present_but_nil"},
			map[string]plgpb.HostPluginServiceClient{"present_but_nil": nil},
		)
		require.ErrorContains(t, err, "controller plugin \"present_but_nil\" not available")
		require.Nil(t, cl)
	})

	t.Run("success", func(t *testing.T) {
		cl, err := pluginClientFactory(
			context.Background(),
			&hostcatalogs.HostCatalog{PluginId: "success"},
			map[string]plgpb.HostPluginServiceClient{"success": plgpb.NewHostPluginServiceClient(nil)},
		)
		require.NoError(t, err)
		require.NotNil(t, cl)
	})
}
