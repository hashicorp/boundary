// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPluginCatalog_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	o, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	plg2 := plugin.TestPlugin(t, conn, "test2")
	new := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())

	tests := []struct {
		name      string
		update    *HostCatalog
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *HostCatalog {
				c := new.clone()
				c.PublicId = "hc_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *HostCatalog {
				c := new.clone()
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "project id",
			update: func() *HostCatalog {
				c := new.clone()
				c.ProjectId = o.PublicId
				return c
			}(),
			fieldMask: []string{"ProjectId"},
		},
		{
			name: "plugin id",
			update: func() *HostCatalog {
				c := new.clone()
				c.PluginId = plg2.GetPublicId()
				return c
			}(),
			fieldMask: []string{"PluginId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}

func TestPluginSet_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	new := TestSet(t, conn, kmsCache, sched, cat, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	})

	tests := []struct {
		name      string
		update    *HostSet
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *HostSet {
				c := new.testCloneHostSet()
				c.PublicId = "hc_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *HostSet {
				c := new.testCloneHostSet()
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "host_plugin_catalog_id",
			update: func() *HostSet {
				c := new.testCloneHostSet()
				c.CatalogId = "stc_01234567890"
				return c
			}(),
			fieldMask: []string{"CatalogId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.testCloneHostSet()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.testCloneHostSet()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}

func (s *HostSet) testCloneHostSet() *HostSet {
	cp := proto.Clone(s.HostSet)
	return &HostSet{
		HostSet: cp.(*store.HostSet),
	}
}
