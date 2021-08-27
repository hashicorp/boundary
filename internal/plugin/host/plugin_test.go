package host

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/plugin/host/store"
)

func TestPlugin_Create(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")

	type args struct {
		pluginName string
		idPrefix   string
		opts       []Option
	}

	tests := []struct {
		name    string
		args    args
		want    *Plugin
		wantErr bool
	}{
		{
			name: "blank-pluginName",
			args: args{
				idPrefix: "prefix",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					IdPrefix: "prefix",
					ScopeId:  scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "blank-idPrefix",
			args: args{
				pluginName: "plugin name",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName: "plugin name",
					ScopeId:    scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				pluginName: "valid-no-options",
				idPrefix:   "valid-no-options",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName: "valid-no-options",
					IdPrefix:   "valid-no-options",
					ScopeId:    scope.Global.String(),
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				pluginName: "valid-with-description",
				idPrefix:   "valid-with-description",
				opts: []Option{
					WithDescription("description"),
				},
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:  "valid-with-description",
					IdPrefix:    "valid-with-description",
					ScopeId:     scope.Global.String(),
					Description: "description",
				},
			},
		},
		{
			name: "valid-pluginName-name-option",
			args: args{
				pluginName: "valid-ignore-pluginName-option",
				idPrefix:   "valid-pluginName-name-option",
				opts: []Option{
					WithName("valid-pluginName-name-option"),
					WithDescription("description"),
				},
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:  "valid-ignore-pluginName-option",
					IdPrefix:    "valid-pluginName-name-option",
					ScopeId:     scope.Global.String(),
					Name:        "valid-pluginName-name-option",
					Description: "description",
				},
			},
		},
		// This must be run after the "valid-no-options" test
		{
			name: "duplicate-pluginName",
			args: args{
				pluginName: "valid-no-options",
				idPrefix:   "duplicate-pluginName",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName: "valid-no-options",
					IdPrefix:   "duplicate-pluginName",
					ScopeId:    scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate-idPrefix",
			args: args{
				pluginName: "duplicate-idPrefix",
				idPrefix:   "valid-no-options",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName: "duplicate-idPrefix",
					IdPrefix:   "valid-no-options",
					ScopeId:    scope.Global.String(),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := NewPlugin(tt.args.pluginName, tt.args.idPrefix, tt.args.opts...)
			require.NotNil(t, got)
			require.Emptyf(t, got.PublicId, "PublicId set")

			id, err := newPluginId()
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

func TestPlugin_Update(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	ctx := context.Background()
	plg := TestPlugin(t, conn, "delete-plugin", "prefix")
	assert.Equal(t, uint32(1), plg.Version)

	plg.Name = "New"
	plg.Description = "Description"
	rowCount, err := w.Update(ctx, plg, []string{"Name", "Description"}, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, rowCount)

	assert.Equal(t, uint32(2), plg.Version)
	assert.Equal(t, "New", plg.Name)
	assert.Equal(t, "Description", plg.Description)
}

func TestPlugin_Delete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	ctx := context.Background()
	plg := TestPlugin(t, conn, "delete-plugin", "prefix")

	deleted, err := w.Delete(ctx, plg)
	require.NoError(t, err)
	require.Equal(t, 1, deleted)
}

func TestPlugin_SetTableName(t *testing.T) {
	defaultTableName := "host_plugin"
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
			def := NewPlugin("", "prefix")
			require.Equal(defaultTableName, def.TableName())
			s := &Plugin{
				Plugin:    &store.Plugin{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
