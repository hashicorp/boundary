package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHostCatalog_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	o, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := TestPlugin(t, conn, "test")
	new := testCatalog(t, conn, plg.GetPublicId(), prj.PublicId)

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
			name: "scope id",
			update: func() *HostCatalog {
				c := new.clone()
				c.ScopeId = o.PublicId
				return c
			}(),
			fieldMask: []string{"ScopeId"},
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

func TestHostSet_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := TestPlugin(t, conn, "test")
	cat := testCatalog(t, conn, plg.GetPublicId(), prj.PublicId)
	sets := TestSets(t, conn, cat.GetPublicId(), 1)

	new := sets[0]

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
			name: "plugin_host_catalog_id",
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

func TestHostPlugin_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	plg := TestPlugin(t, conn, "test")

	newPlugin := plg

	tests := []struct {
		name      string
		update    *Plugin
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *Plugin {
				c := newPlugin.testClonePlugin()
				c.PublicId = "hc_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *Plugin {
				c := newPlugin.testClonePlugin()
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "pluginName",
			update: func() *Plugin {
				c := newPlugin.testClonePlugin()
				c.PluginName = "different pluginName"
				return c
			}(),
			fieldMask: []string{"PluginName"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := newPlugin.testClonePlugin()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := newPlugin.testClonePlugin()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}

func (c *HostSet) testCloneHostSet() *HostSet {
	cp := proto.Clone(c.HostSet)
	return &HostSet{
		HostSet: cp.(*store.HostSet),
	}
}

func (c *Plugin) testClonePlugin() *Plugin {
	cp := proto.Clone(c.Plugin)
	return &Plugin{
		Plugin: cp.(*store.Plugin),
	}
}
