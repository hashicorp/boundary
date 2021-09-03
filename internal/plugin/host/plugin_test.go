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
		semVer     string
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
				semVer:   "0.0.1",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					IdPrefix:        "prefix",
					SemanticVersion: "0.0.1",
					ScopeId:         scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "blank-idPrefix",
			args: args{
				pluginName: "plugin name",
				semVer:     "0.0.1",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:      "plugin name",
					SemanticVersion: "0.0.1",
					ScopeId:         scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "idprefix-capitalized",
			args: args{
				pluginName: "idprefixcapitalized",
				idPrefix:   "IdPrefixCapitalized",
				semVer:     "0.0.1",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:      "idprefixcapitalized",
					IdPrefix:        "IdPrefixCapitalized",
					SemanticVersion: "0.0.1",
					ScopeId:         scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "idprefix-space",
			args: args{
				pluginName: "idprefix space",
				idPrefix:   "idprefix space",
				semVer:     "0.0.1",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:      "idprefix space",
					IdPrefix:        "idprefix space",
					SemanticVersion: "0.0.1",
					ScopeId:         scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "pluginName-capitalized",
			args: args{
				pluginName: "PluginNameCapitalized",
				idPrefix:   "pluginnamecapitalized",
				semVer:     "0.0.1",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:      "PluginNameCapitalized",
					IdPrefix:        "pluginnamecapitalized",
					SemanticVersion: "0.0.1",
					ScopeId:         scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid-semver",
			args: args{
				pluginName: "invalidsemver",
				idPrefix:   "invalidsemver",
				semVer:     "0.0.1.0",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:      "invalidsemver",
					IdPrefix:        "invalidsemver",
					SemanticVersion: "0.0.1.0",
					ScopeId:         scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				pluginName: "validnooptions",
				idPrefix:   "validnooptions",
				semVer:     "0.0.1",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:      "validnooptions",
					IdPrefix:        "validnooptions",
					SemanticVersion: "0.0.1",
					ScopeId:         scope.Global.String(),
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				pluginName: "validwithdescription",
				idPrefix:   "validwithdescription",
				semVer:     "0.0.1",
				opts: []Option{
					WithDescription("description"),
				},
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:      "validwithdescription",
					IdPrefix:        "validwithdescription",
					SemanticVersion: "0.0.1",
					ScopeId:         scope.Global.String(),
					Description:     "description",
				},
			},
		},
		{
			name: "valid-pluginName-name-option",
			args: args{
				pluginName: "validpluginnamenameoption",
				idPrefix:   "validpluginnamenameoption",
				semVer:     "0.0.1",
				opts: []Option{
					WithName("valid-pluginName-name-option"),
					WithDescription("description"),
				},
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:      "validpluginnamenameoption",
					IdPrefix:        "validpluginnamenameoption",
					SemanticVersion: "0.0.1",
					ScopeId:         scope.Global.String(),
					Name:            "valid-pluginName-name-option",
					Description:     "description",
				},
			},
		},
		// This must be run after the "valid-no-options" test
		{
			name: "duplicate-pluginName",
			args: args{
				pluginName: "validnooptions",
				idPrefix:   "duplicatepluginname",
				semVer:     "0.0.1",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:      "validnooptions",
					IdPrefix:        "duplicatepluginname",
					SemanticVersion: "0.0.1",
					ScopeId:         scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate-idPrefix",
			args: args{
				pluginName: "duplicateidprefix",
				idPrefix:   "validnooptions",
				semVer:     "0.0.1",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					PluginName:      "duplicateidprefix",
					IdPrefix:        "validnooptions",
					SemanticVersion: "0.0.1",
					ScopeId:         scope.Global.String(),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := NewPlugin(tt.args.pluginName, tt.args.idPrefix, tt.args.semVer, tt.args.opts...)
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
	defaultTableName := "plugin_host"
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
			def := NewPlugin("", "prefix", "0.0.1")
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
