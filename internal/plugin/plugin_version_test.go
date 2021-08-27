package plugin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/plugin/store"
)

func TestPluginVersion_Create(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	plg := testPlugin(t, conn, "test")

	type args struct {
		pluginid string
		ver      string
		opts     []Option
	}

	tests := []struct {
		name    string
		args    args
		want    *PluginVersion
		wantErr bool
	}{
		{
			name: "blank-version",
			args: args{
				pluginid: plg.GetPublicId(),
			},
			want: &PluginVersion{
				PluginVersion: &store.PluginVersion{
					PluginId: plg.GetPublicId(),
				},
			},
			wantErr: true,
		},
		{
			name: "short-version",
			args: args{
				pluginid: plg.GetPublicId(),
				ver:      "1234",
			},
			want: &PluginVersion{
				PluginVersion: &store.PluginVersion{
					SemanticVersion: "1234",
					PluginId:        plg.GetPublicId(),
				},
			},
			wantErr: true,
		},
		{
			name: "blank-pluginId",
			args: args{
				ver: "0.0.1",
			},
			want: &PluginVersion{
				PluginVersion: &store.PluginVersion{
					SemanticVersion: "0.0.1",
				},
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				pluginid: plg.GetPublicId(),
				ver:      "0.0.1",
			},
			want: &PluginVersion{
				PluginVersion: &store.PluginVersion{
					PluginId:        plg.GetPublicId(),
					SemanticVersion: "0.0.1",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := NewPluginVersion(tt.args.pluginid, tt.args.ver)
			require.NotNil(t, got)
			require.Emptyf(t, got.PublicId, "PublicId set")

			id, err := newPluginVersionId()
			require.NoError(t, err)
			got.PublicId = id

			tt.want.PublicId = id
			assert.Equal(t, tt.want, got)

			w := db.New(conn)
			err = w.Create(context.Background(), got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPluginVersion_Delete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	ctx := context.Background()
	plg := testPlugin(t, conn, "test")
	plgver := testPluginVersion(t, conn, plg.GetPublicId(), "0.0.1")

	deleted, err := w.Delete(ctx, plgver)
	require.NoError(t, err)
	require.Equal(t, 1, deleted)
}

func TestPluginVersion_SetTableName(t *testing.T) {
	defaultTableName := "plugin_version"
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
			def := NewPluginVersion("test", "0.0.1")
			require.Equal(defaultTableName, def.TableName())
			s := &PluginVersion{
				PluginVersion: &store.PluginVersion{},
				tableName:     tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
