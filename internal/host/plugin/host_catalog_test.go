package plugin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestHostCatalog_Create(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test", "prefix")

	type args struct {
		pluginId string
		scopeId  string
		opts     []Option
	}

	tests := []struct {
		name          string
		args          args
		want          *HostCatalog
		wantErr       bool
		wantCreateErr bool
	}{
		{
			name: "blank-scopeId",
			args: args{
				pluginId: plg.GetPublicId(),
				scopeId:  "",
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PluginId:   plg.GetPublicId(),
					Attributes: []byte("{}"),
				},
			},
			wantCreateErr: true,
		},
		{
			name: "blank-pluginId",
			args: args{
				pluginId: "",
				scopeId:  prj.GetPublicId(),
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:    prj.GetPublicId(),
					Attributes: []byte("{}"),
				},
			},
			wantCreateErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				pluginId: plg.GetPublicId(),
				scopeId:  prj.GetPublicId(),
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PluginId:   plg.GetPublicId(),
					ScopeId:    prj.GetPublicId(),
					Attributes: []byte("{}"),
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				pluginId: plg.GetPublicId(),
				scopeId:  prj.GetPublicId(),
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PluginId:   plg.GetPublicId(),
					ScopeId:    prj.GetPublicId(),
					Name:       "test-name",
					Attributes: []byte("{}"),
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				pluginId: plg.GetPublicId(),
				scopeId:  prj.GetPublicId(),
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PluginId:    plg.GetPublicId(),
					ScopeId:     prj.GetPublicId(),
					Description: "test-description",
					Attributes:  []byte("{}"),
				},
			},
		},
		{
			name: "valid-with-attributes",
			args: args{
				pluginId: plg.GetPublicId(),
				scopeId:  prj.GetPublicId(),
				opts: []Option{
					WithAttributes(map[string]interface{}{"foo": "bar"}),
				},
			},
			want: func() *HostCatalog {
				hc := &HostCatalog{
					HostCatalog: &store.HostCatalog{
						PluginId: plg.GetPublicId(),
						ScopeId:  prj.GetPublicId(),
					},
				}
				var err error
				hc.Attributes, err = json.Marshal(map[string]interface{}{"foo": "bar"})
				require.NoError(t, err)
				return hc
			}(),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewHostCatalog(context.Background(), tt.args.pluginId, tt.args.scopeId, tt.args.opts...)
			require.NoError(t, err)
			require.NotNil(t, got)

			assert.Emptyf(t, got.PublicId, "PublicId set")
			assert.Equal(t, tt.want, got)

			id, err := newHostCatalogId()
			assert.NoError(t, err)

			tt.want.PublicId = id
			got.PublicId = id

			w := db.New(conn)
			err = w.Create(context.Background(), got)
			if tt.wantCreateErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				found := &HostCatalog{
					HostCatalog: &store.HostCatalog{
						PublicId: id,
					},
				}
				require.NoError(t, w.LookupById(context.Background(), found))
				assert.Empty(t, cmp.Diff(got.HostCatalog, found.HostCatalog, protocmp.Transform()), "%q compared to %q", got.Attributes, found.Attributes)
			}
		})
	}
}

func TestHostCatalog_Create_DuplicateNames(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	_, prj2 := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test1", "prefix1")
	plg2 := host.TestPlugin(t, conn, "test2", "prefix2")

	got, err := NewHostCatalog(context.Background(), plg.GetPublicId(), prj.GetPublicId(), WithName("duplicate"))
	require.NoError(t, err)
	got.PublicId, err = newHostCatalogId()
	require.NoError(t, err)
	w.Create(ctx, got)

	// Can't create another resource with the same pluginName in the same scope
	got.PublicId, err = newHostCatalogId()
	require.NoError(t, err)
	assert.Error(t, w.Create(ctx, got))

	// Can't create another resource with same pluginName in same scope even for different plugin
	got, err = NewHostCatalog(context.Background(), plg2.GetPublicId(), prj.GetPublicId(), WithName("duplicate"))
	require.NoError(t, err)
	got.PublicId, err = newHostCatalogId()
	require.NoError(t, err)
	assert.Error(t, w.Create(ctx, got))

	// Can create another resource with same pluginName in different scope even for same plugin
	got, err = NewHostCatalog(context.Background(), plg.GetPublicId(), prj2.GetPublicId(), WithName("duplicate"))
	require.NoError(t, err)
	got.PublicId, err = newHostCatalogId()
	require.NoError(t, err)
	assert.NoError(t, w.Create(ctx, got))
}

func TestHostCatalog_Delete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test", "prefix")
	cat := TestCatalog(t, conn, plg.GetPublicId(), prj.GetPublicId())
	ignoredCat := TestCatalog(t, conn, plg.GetPublicId(), prj.GetPublicId())
	_ = ignoredCat
	tests := []struct {
		name        string
		cat         *HostCatalog
		rowsDeleted int
	}{
		{
			name: "valid",
			cat: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PublicId: cat.GetPublicId(),
				},
			},
			rowsDeleted: 1,
		},
		{
			name: "bad-id",
			cat: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PublicId: "bad-id",
				},
			},
			rowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			w := db.New(conn)
			deletedRows, err := w.Delete(ctx, tt.cat)
			require.NoError(t, err)
			assert.Equal(t, tt.rowsDeleted, deletedRows)

			err = w.LookupById(ctx, tt.cat)
			require.Error(t, err)
			assert.True(t, errors.IsNotFoundError(err))
		})
	}
}

func TestHostCatalog_Delete_Cascading(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	ctx := context.Background()

	t.Run("delete-scope", func(t *testing.T) {
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		plg := host.TestPlugin(t, conn, "deletescope", "deletescope")
		cat := TestCatalog(t, conn, plg.GetPublicId(), prj.GetPublicId())

		deleted, err := w.Delete(ctx, prj)
		require.NoError(t, err)
		require.Equal(t, 1, deleted)

		err = w.LookupById(ctx, cat)
		require.Error(t, err)
		assert.True(t, errors.IsNotFoundError(err))
	})

	t.Run("delete-plugin", func(t *testing.T) {
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		plg := host.TestPlugin(t, conn, "deleteplugin", "deleteplugin")
		cat := TestCatalog(t, conn, plg.GetPublicId(), prj.GetPublicId())

		deleted, err := w.Delete(ctx, plg)
		require.NoError(t, err)
		require.Equal(t, 1, deleted)

		err = w.LookupById(ctx, cat)
		require.Error(t, err)
		assert.True(t, errors.IsNotFoundError(err))
	})
}

func TestHostCatalog_SetTableName(t *testing.T) {
	defaultTableName := "host_plugin_catalog"
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
			def, err := NewHostCatalog(context.Background(), "", "")
			require.NoError(t, err)
			require.Equal(t, defaultTableName, def.TableName())
			s := &HostCatalog{
				HostCatalog: &store.HostCatalog{},
				tableName:   tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(t, tt.want, s.TableName())
		})
	}
}
