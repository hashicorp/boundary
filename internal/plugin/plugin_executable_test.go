package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/plugin/store"
)

func TestPluginExecutable_Create(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	plg := testPlugin(t, conn, "test")
	plgVer := testPluginVersion(t, conn, plg.GetPublicId(), "0.0.1")

	sample := []byte("this is just an example")

	type args struct {
		verId string
		os, arch string
		exe []byte
		opts     []Option
	}

	tests := []struct {
		name    string
		args    args
		want    *PluginExecutable
		wantErr bool
	}{
		{
			name: "blank-os",
			args: args{
				verId: plgVer.GetPublicId(),
				exe: sample,
			},
			want: &PluginExecutable{
				PluginExecutable: &store.PluginExecutable{
					VersionId: plgVer.GetPublicId(),
					Executable: sample,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := NewPluginExecutable(tt.args.verId, tt.args.os, tt.args.arch, tt.args.exe)
			require.NotNil(t, got)

			w := db.New(conn)
			err := w.Create(context.Background(), got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPluginExecutable_Delete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	ctx := context.Background()
	os := "windows"
	arch := "amd64"
	exe := []byte("test")

	t.Run("cascade-plugin", func(t *testing.T) {
		plg := testPlugin(t, conn, "cascade-plugin")
		plgVer := testPluginVersion(t, conn, plg.GetPublicId(), "0.0.1")

		plgExe := NewPluginExecutable(plgVer.GetPublicId(), os, arch, exe)
		require.NoError(t, w.Create(ctx, plgExe))

		deleted, err := w.Delete(ctx, plg)
		require.NoError(t, err)
		require.Equal(t, 1, deleted)

		err = w.LookupWhere(ctx, plgExe, "version_id=?", plgVer.GetPublicId())
		require.Error(t, err)
		assert.True(t, errors.IsNotFoundError(err))
	})

	t.Run("cascade-version", func(t *testing.T) {
		plg := testPlugin(t, conn, "cascade-version")
		plgVer := testPluginVersion(t, conn, plg.GetPublicId(), "0.0.1")

		plgExe := NewPluginExecutable(plgVer.GetPublicId(), os, arch, exe)
		require.NoError(t, w.Create(ctx, plgExe))

		deleted, err := w.Delete(ctx, plgVer)
		require.NoError(t, err)
		require.Equal(t, 1, deleted)

		err = w.LookupWhere(ctx, plgExe, "version_id=?", plgVer.GetPublicId())
		require.Error(t, err)
		assert.True(t, errors.IsNotFoundError(err))
	})

	t.Run("direct-delete", func(t *testing.T) {
		plg := testPlugin(t, conn, "direct-delete")
		plgVer := testPluginVersion(t, conn, plg.GetPublicId(), "0.0.1")

		plgExe := NewPluginExecutable(plgVer.GetPublicId(), os, arch, exe)
		require.NoError(t, w.Create(ctx, plgExe))

		deleted, err := w.Delete(ctx, plgExe)
		require.NoError(t, err)
		require.Equal(t, 1, deleted)

		err = w.LookupWhere(ctx, plgExe, "version_id=?", plgVer.GetPublicId())
		require.Error(t, err)
		assert.True(t, errors.IsNotFoundError(err))
	})
}

func TestPluginExecutable_SetTableName(t *testing.T) {
	defaultTableName := "plugin_executable"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-pluginName",
			initialName: "",
			setNameTo:   "new-pluginName",
			want:        "new-pluginName",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := NewPluginExecutable("versionid", "os", "arch", []byte("test"))
			require.Equal(defaultTableName, def.TableName())
			s := &PluginExecutable{
				PluginExecutable: &store.PluginExecutable{},
				tableName:     tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
