// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/plugin/store"
)

func TestPlugin_Create(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")

	tests := []struct {
		name    string
		opts    []Option
		want    *Plugin
		wantErr bool
	}{
		{
			name: "valid",
			want: &Plugin{
				Plugin: &store.Plugin{
					ScopeId: scope.Global.String(),
				},
			},
		},
		{
			name: "with-name",
			opts: []Option{WithName("foo")},
			want: &Plugin{
				Plugin: &store.Plugin{
					Name:    "foo",
					ScopeId: scope.Global.String(),
				},
			},
		},
		{
			name: "with-description",
			opts: []Option{WithDescription("foo")},
			want: &Plugin{
				Plugin: &store.Plugin{
					Description: "foo",
					ScopeId:     scope.Global.String(),
				},
			},
		},
		// This must be run after the "valid-no-options" test
		{
			name: "duplicate-name",
			opts: []Option{WithName("foo")},
			want: &Plugin{
				Plugin: &store.Plugin{
					Name:    "foo",
					ScopeId: scope.Global.String(),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := NewPlugin(tt.opts...)
			require.NotNil(t, got)
			require.Emptyf(t, got.PublicId, "PublicId set")

			id, err := newPluginId(ctx)
			require.NoError(t, err)
			got.PublicId = id

			tt.want.PublicId = id
			assert.Equal(t, tt.want, got)

			w := db.New(conn)
			err = w.Create(ctx, got)
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
	plg := TestPlugin(t, conn, "delete-plugin")
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
	plg := TestPlugin(t, conn, "delete-plugin")

	deleted, err := w.Delete(ctx, plg)
	require.NoError(t, err)
	require.Equal(t, 1, deleted)
}

func TestPlugin_SetTableName(t *testing.T) {
	defaultTableName := "plugin"
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
			def := NewPlugin()
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
