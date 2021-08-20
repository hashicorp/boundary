package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
)

func TestPlugin_Create(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")

	type args struct {
		name, prefix string
		opts         []Option
	}

	tests := []struct {
		name    string
		args    args
		want    *Plugin
		wantErr bool
	}{
		{
			name: "blank-name",
			args: args{
				prefix: "prefix",
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
			name: "blank-prefix",
			args: args{
				name: "name",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					Name:    "name",
					ScopeId: scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "blank-both",
			args: args{},
			want: &Plugin{
				Plugin: &store.Plugin{
					ScopeId: scope.Global.String(),
				},
			},
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				name:   "valid-no-options",
				prefix: "valid-no-options",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					ScopeId:  scope.Global.String(),
					Name:     "valid-no-options",
					IdPrefix: "valid-no-options",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				name:   "valid-with-description",
				prefix: "valid-with-description",
				opts: []Option{
					WithDescription("description"),
				},
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					ScopeId:     scope.Global.String(),
					Name:        "valid-with-description",
					IdPrefix:    "valid-with-description",
					Description: "description",
				},
			},
		},
		{
			name: "valid-ignore-name-option",
			args: args{
				name:   "valid-ignore-name-option",
				prefix: "valid-ignore-name-option",
				opts: []Option{
					WithName("ignore-this"),
					WithDescription("description"),
				},
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					ScopeId:     scope.Global.String(),
					Name:        "valid-ignore-name-option",
					IdPrefix:    "valid-ignore-name-option",
					Description: "description",
				},
			},
		},
		// This must be run after the "valid-no-options" test
		{
			name: "duplicate-name",
			args: args{
				name:   "valid-no-options",
				prefix: "duplicate-name",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					ScopeId:  scope.Global.String(),
					Name:     "valid-no-options",
					IdPrefix: "duplicate-name",
				},
			},
			wantErr: true,
		},
		// This must be run after the "valid-no-options" test
		{
			name: "duplicate-prefix",
			args: args{
				name:   "duplicate-prefix",
				prefix: "valid-no-options",
			},
			want: &Plugin{
				Plugin: &store.Plugin{
					ScopeId:  scope.Global.String(),
					Name:     "duplicate-prefix",
					IdPrefix: "valid-no-options",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := NewPlugin(tt.args.name, tt.args.prefix, tt.args.opts...)
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

func TestPlugin_SetTableName(t *testing.T) {
	defaultTableName := "host_plugin"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
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
			def := NewPlugin("", "")
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
