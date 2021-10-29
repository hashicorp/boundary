package plugin

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestHostCatalog_Create(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")

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
					Attributes: []byte{},
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
					Attributes: []byte{},
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
					Attributes: []byte{},
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
					Attributes: []byte{},
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
					Attributes:  []byte{},
				},
			},
		},
		{
			name: "valid-with-attributes",
			args: args{
				pluginId: plg.GetPublicId(),
				scopeId:  prj.GetPublicId(),
				opts: []Option{
					WithAttributes(&structpb.Struct{Fields: map[string]*structpb.Value{"foo": structpb.NewStringValue("bar")}}),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PluginId:   plg.GetPublicId(),
					ScopeId:    prj.GetPublicId(),
					Attributes: []byte{},
				},
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{"foo": structpb.NewStringValue("bar")}},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := NewHostCatalog(ctx, tt.args.scopeId, tt.args.pluginId, tt.args.opts...)
			require.NotNil(t, got)

			assert.Empty(t, got.PublicId, "PublicId should not be set")
			assert.Equal(t, tt.want, got)

			id, err := newHostCatalogId(ctx)
			assert.NoError(t, err)

			tt.want.PublicId = id
			got.PublicId = id

			w := db.New(conn)
			err = w.Create(ctx, got)
			if tt.wantCreateErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				found := &HostCatalog{
					HostCatalog: &store.HostCatalog{
						PublicId: id,
					},
				}
				require.NoError(t, w.LookupById(ctx, found))
				assert.Empty(t, cmp.Diff(got.HostCatalog, found.HostCatalog, protocmp.Transform()), "%q compared to %q", got.HostCatalog.Attributes, found.HostCatalog.Attributes)
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
	plg := host.TestPlugin(t, conn, "test1")
	plg2 := host.TestPlugin(t, conn, "test2")

	got := NewHostCatalog(ctx, prj.GetPublicId(), plg.GetPublicId(), WithName("duplicate"))
	require.NotNil(t, got)
	var err error
	got.PublicId, err = newHostCatalogId(ctx)
	require.NoError(t, err)
	require.NoError(t, w.Create(ctx, got))

	// Can't create another resource with the same name in the same scope
	got.PublicId, err = newHostCatalogId(ctx)
	require.NoError(t, err)
	assert.Error(t, w.Create(ctx, got))

	// Can't create another resource with same name in same scope even for different plugin
	got = NewHostCatalog(ctx, prj.GetPublicId(), plg2.GetPublicId(), WithName("duplicate"))
	require.NotNil(t, got)
	got.PublicId, err = newHostCatalogId(ctx)
	require.NoError(t, err)
	assert.Error(t, w.Create(ctx, got))

	// Can create another resource with same name in different scope even for same plugin
	got = NewHostCatalog(ctx, prj2.GetPublicId(), plg.GetPublicId(), WithName("duplicate"))
	require.NotNil(t, got)
	got.PublicId, err = newHostCatalogId(ctx)
	require.NoError(t, err)
	assert.NoError(t, w.Create(ctx, got))
}

func TestHostCatalog_Delete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	ignoredCat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
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
		plg := host.TestPlugin(t, conn, "deletescope")
		cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())

		deleted, err := w.Delete(ctx, prj)
		require.NoError(t, err)
		require.Equal(t, 1, deleted)

		err = w.LookupById(ctx, cat)
		require.Error(t, err)
		assert.True(t, errors.IsNotFoundError(err))
	})

	t.Run("delete-plugin", func(t *testing.T) {
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		plg := host.TestPlugin(t, conn, "deleteplugin")
		cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())

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
			def := NewHostCatalog(context.Background(), "", "")
			require.NotNil(t, def)
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

// testStoreHostCatalogBase is a base store.HostCatalog struct that
// embeds store.HostCatalog without any other interfaces implemented
// other than Tabler to give the correct table name. This ensures
// that a record can be written as-is without callbacks, etc, for
// point-in-time testing of various methods.
type testStoreHostCatalog struct {
	*store.HostCatalog
}

func (c *testStoreHostCatalog) TableName() string { return "host_plugin_catalog" }

func TestHostCatalog_AttributesUnmarsahlOnLookup(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")

	expected := mustStruct(map[string]interface{}{
		"foo": "bar",
	})
	attrsB, err := proto.Marshal(expected)
	require.NoError(err)
	require.NotNil(attrsB)

	id, err := newHostCatalogId(ctx)
	require.NoError(err)

	// Create a host catalog record using store.HostCatalog first,
	// without higher-level logic
	shc := &testStoreHostCatalog{
		HostCatalog: &store.HostCatalog{
			PublicId:   id,
			ScopeId:    prj.PublicId,
			PluginId:   plg.PublicId,
			Attributes: attrsB,
		},
	}

	w := db.New(conn)
	err = w.Create(ctx, shc)
	require.NoError(err)

	found := &HostCatalog{
		HostCatalog: &store.HostCatalog{
			PublicId: id,
		},
	}

	require.NoError(w.LookupById(ctx, found))
	require.NotNil(found.Attributes)
	require.Empty(cmp.Diff(expected, found.Attributes, protocmp.Transform()))
	require.Nil(found.HostCatalog.Attributes)
}

func TestHostCatalog_AttributesMarsahlOnSave(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")

	attrsCreate := mustStruct(map[string]interface{}{
		"foo": "bar",
	})
	attrsUpdate := mustStruct(map[string]interface{}{
		"baz": "qux",
	})
	// Create using the higher-level HostCatalog object first without
	// helper/validation methods.
	hc := NewHostCatalog(ctx, prj.GetPublicId(), plg.GetPublicId(), WithAttributes(attrsCreate))
	id, err := newHostCatalogId(ctx)
	require.NoError(t, err)
	hc.PublicId = id

	w := db.New(conn)

	t.Run("create", func(t *testing.T) {
		err = w.Create(ctx, hc)
		require.NoError(t, err)
		require.Nil(t, hc.HostCatalog.Attributes, "wire data should be niled out after creation")

		// Lookup the host catalog record using store.HostCatalog only,
		// ensuring that no callbacks interfere.
		found := &testStoreHostCatalog{
			HostCatalog: &store.HostCatalog{
				PublicId: id,
			},
		}

		require.NoError(t, w.LookupById(ctx, found))
		require.NotNil(t, found.HostCatalog.Attributes)

		expected, err := proto.Marshal(attrsCreate)
		require.NoError(t, err)
		require.NotNil(t, expected)
		require.Equal(t, expected, found.HostCatalog.Attributes)
	})

	t.Run("update", func(t *testing.T) {
		hc.Attributes = attrsUpdate
		numUpdated, err := w.Update(ctx, hc, []string{"attributes"}, []string{})
		require.NoError(t, err)
		require.Equal(t, 1, numUpdated)
		require.Nil(t, hc.HostCatalog.Attributes, "wire data should remain nil after update")

		// Lookup the host catalog record using store.HostCatalog only,
		// ensuring that no callbacks interfere.
		found := &testStoreHostCatalog{
			HostCatalog: &store.HostCatalog{
				PublicId: id,
			},
		}

		require.NoError(t, w.LookupById(ctx, found))
		require.NotNil(t, found.HostCatalog.Attributes)

		expected, err := proto.Marshal(attrsUpdate)
		require.NoError(t, err)
		require.NotNil(t, expected)
		require.Equal(t, expected, found.HostCatalog.Attributes)
	})
}

func TestHostCatalog_marshalAttributes_empty(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		hc := &HostCatalog{HostCatalog: &store.HostCatalog{}}
		hc.marshalAttributes()
		assert.Equal(t, []byte{}, hc.HostCatalog.Attributes)
	})
	t.Run("empty struct", func(t *testing.T) {
		hc := &HostCatalog{
			HostCatalog: &store.HostCatalog{},
			Attributes:  &structpb.Struct{},
		}
		hc.marshalAttributes()
		assert.Equal(t, []byte{}, hc.HostCatalog.Attributes)
	})
}

func TestHostCatalog_GetAttributes(t *testing.T) {
	t.Run("type", func(t *testing.T) {
		require.IsType(t, &structpb.Struct{}, (&HostCatalog{}).GetAttributes())
	})

	t.Run("nil", func(t *testing.T) {
		require.Nil(t, (*HostCatalog)(nil).GetAttributes())
	})

	t.Run("not nil", func(t *testing.T) {
		expected := mustStruct(map[string]interface{}{"foo": "bar"})
		actual := (&HostCatalog{Attributes: mustStruct(map[string]interface{}{"foo": "bar"})}).GetAttributes()
		require.Empty(t, cmp.Diff(expected, actual, protocmp.Transform()))
	})
}

func TestHostCatalog_Clone_EmptyAttributes(t *testing.T) {
	t.Run("embedded", func(t *testing.T) {
		c := &HostCatalog{
			HostCatalog: &store.HostCatalog{
				Attributes: make([]byte, 0),
			},
		}
		actual := c.clone()
		assert.NotNil(t, actual.HostCatalog.Attributes)
		assert.Nil(t, actual.Attributes)
	})

	t.Run("top", func(t *testing.T) {
		c := &HostCatalog{
			HostCatalog: &store.HostCatalog{},
			Attributes:  &structpb.Struct{},
		}
		actual := c.clone()
		assert.Nil(t, actual.HostCatalog.Attributes)
		assert.NotNil(t, actual.Attributes)
	})

	t.Run("both", func(t *testing.T) {
		c := &HostCatalog{
			HostCatalog: &store.HostCatalog{
				Attributes: make([]byte, 0),
			},
			Attributes: &structpb.Struct{},
		}
		actual := c.clone()
		assert.NotNil(t, actual.HostCatalog.Attributes)
		assert.NotNil(t, actual.Attributes)
	})
}
