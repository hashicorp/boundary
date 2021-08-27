package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPlugin_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	plg := testPlugin(t, conn, "test")

	newPlugin := plg

	tests := []struct {
		name      string
		update    *plugin
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *plugin {
				c := newPlugin.testClonePlugin()
				c.PublicId = "pi_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "scope",
			update: func() *plugin {
				c := newPlugin.testClonePlugin()
				c.ScopeId = "o_1234567890"
				return c
			}(),
			fieldMask: []string{"ScopeId"},
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

func TestPluginVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	plg := testPlugin(t, conn, "test")
	plg2 := testPlugin(t, conn, "test2")
	plgVer := testPluginVersion(t, conn, plg.GetPublicId(), "0.0.1")

	newPluginVer := plgVer

	tests := []struct {
		name      string
		update    *PluginVersion
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *PluginVersion {
				c := newPluginVer.testClonePluginVersion()
				c.PublicId = "hc_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *PluginVersion {
				c := newPluginVer.testClonePluginVersion()
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "plugin_id",
			update: func() *PluginVersion {
				c := newPluginVer.testClonePluginVersion()
				c.PluginId = plg2.GetPublicId()
				return c
			}(),
			fieldMask: []string{"PluginId"},
		},
		{
			name: "version",
			update: func() *PluginVersion {
				c := newPluginVer.testClonePluginVersion()
				c.SemanticVersion = "0.0.2"
				return c
			}(),
			fieldMask: []string{"SymanticVersion"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := newPluginVer.testClonePluginVersion()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := newPluginVer.testClonePluginVersion()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}

func TestPluginExecutable_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	plg := testPlugin(t, conn, "test")
	plgVer := testPluginVersion(t, conn, plg.GetPublicId(), "0.0.1")
	plgExe := testPluginExecutable(t, conn, plgVer.GetPublicId(), "windows", "amd64", []byte("test"))

	newPluginExe := plgExe

	tests := []struct {
		name      string
		update    *PluginExecutable
		fieldMask []string
	}{
		{
			name: "version_id",
			update: func() *PluginExecutable {
				c := newPluginExe.testClonePluginExecutable()
				c.VersionId = "hc_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"VersionId"},
		},
		{
			name: "create time",
			update: func() *PluginExecutable {
				c := newPluginExe.testClonePluginExecutable()
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "os",
			update: func() *PluginExecutable {
				c := newPluginExe.testClonePluginExecutable()
				c.OperatingSystem = "linux"
				return c
			}(),
			fieldMask: []string{"OperatingSystem"},
		},
		{
			name: "arch",
			update: func() *PluginExecutable {
				c := newPluginExe.testClonePluginExecutable()
				c.Architecture = "arm"
				return c
			}(),
			fieldMask: []string{"Architecture"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := newPluginExe.testClonePluginExecutable()
			err := w.LookupWhere(context.Background(), orig, "version_id=?", plgVer.GetPublicId())
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := newPluginExe.testClonePluginExecutable()
			err = w.LookupWhere(context.Background(), after, "version_id=?", plgVer.GetPublicId())
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}

func (c *plugin) testClonePlugin() *plugin {
	cp := proto.Clone(c.Plugin)
	return &plugin{
		Plugin: cp.(*store.Plugin),
	}
}

func (c *PluginVersion) testClonePluginVersion() *PluginVersion {
	cp := proto.Clone(c.PluginVersion)
	return &PluginVersion{
		PluginVersion: cp.(*store.PluginVersion),
	}
}

func (c *PluginExecutable) testClonePluginExecutable() *PluginExecutable {
	cp := proto.Clone(c.PluginExecutable)
	return &PluginExecutable{
		PluginExecutable: cp.(*store.PluginExecutable),
	}
}
