// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/mr-tron/base58"
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
	plg := plugin.TestPlugin(t, conn, "test")

	type args struct {
		pluginId  string
		projectId string
		opts      []Option
	}

	tests := []struct {
		name          string
		args          args
		want          *HostCatalog
		wantErr       bool
		wantCreateErr bool
	}{
		{
			name: "blank-projectId",
			args: args{
				pluginId:  plg.GetPublicId(),
				projectId: "",
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
				pluginId:  "",
				projectId: prj.GetPublicId(),
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ProjectId:  prj.GetPublicId(),
					Attributes: []byte{},
				},
			},
			wantCreateErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				pluginId:  plg.GetPublicId(),
				projectId: prj.GetPublicId(),
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PluginId:   plg.GetPublicId(),
					ProjectId:  prj.GetPublicId(),
					Attributes: []byte{},
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				pluginId:  plg.GetPublicId(),
				projectId: prj.GetPublicId(),
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PluginId:   plg.GetPublicId(),
					ProjectId:  prj.GetPublicId(),
					Name:       "test-name",
					Attributes: []byte{},
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				pluginId:  plg.GetPublicId(),
				projectId: prj.GetPublicId(),
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PluginId:    plg.GetPublicId(),
					ProjectId:   prj.GetPublicId(),
					Description: "test-description",
					Attributes:  []byte{},
				},
			},
		},
		{
			name: "valid-with-attributes",
			args: args{
				pluginId:  plg.GetPublicId(),
				projectId: prj.GetPublicId(),
				opts: []Option{
					WithAttributes(&structpb.Struct{Fields: map[string]*structpb.Value{"foo": structpb.NewStringValue("bar")}}),
				},
			},
			want: func() *HostCatalog {
				hc := &HostCatalog{
					HostCatalog: &store.HostCatalog{
						PluginId:  plg.GetPublicId(),
						ProjectId: prj.GetPublicId(),
					},
				}
				var err error
				hc.Attributes, err = proto.Marshal(&structpb.Struct{Fields: map[string]*structpb.Value{"foo": structpb.NewStringValue("bar")}})
				require.NoError(t, err)
				return hc
			}(),
		},
		{
			name: "valid-with-worker-filter",
			args: args{
				pluginId:  plg.GetPublicId(),
				projectId: prj.GetPublicId(),
				opts: []Option{
					WithWorkerFilter(`"test" in "/tags/type"`),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PluginId:     plg.GetPublicId(),
					ProjectId:    prj.GetPublicId(),
					Attributes:   []byte{},
					WorkerFilter: `"test" in "/tags/type"`,
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewHostCatalog(ctx, tt.args.projectId, tt.args.pluginId, tt.args.opts...)
			require.NoError(t, err)
			require.NotNil(t, got)

			assert.Emptyf(t, got.PublicId, "PublicId set")
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
	plg := plugin.TestPlugin(t, conn, "test1")
	plg2 := plugin.TestPlugin(t, conn, "test2")

	got, err := NewHostCatalog(ctx, prj.GetPublicId(), plg.GetPublicId(), WithName("duplicate"))
	require.NoError(t, err)
	got.PublicId, err = newHostCatalogId(ctx)
	require.NoError(t, err)
	require.NoError(t, w.Create(ctx, got))

	// Can't create another resource with the same name in the same project
	got.PublicId, err = newHostCatalogId(ctx)
	require.NoError(t, err)
	assert.Error(t, w.Create(ctx, got))

	// Can't create another resource with same name in same project even for different plugin
	got, err = NewHostCatalog(ctx, prj.GetPublicId(), plg2.GetPublicId(), WithName("duplicate"))
	require.NoError(t, err)
	got.PublicId, err = newHostCatalogId(ctx)
	require.NoError(t, err)
	assert.Error(t, w.Create(ctx, got))

	// Can create another resource with same name in different project even for same plugin
	got, err = NewHostCatalog(ctx, prj2.GetPublicId(), plg.GetPublicId(), WithName("duplicate"))
	require.NoError(t, err)
	got.PublicId, err = newHostCatalogId(ctx)
	require.NoError(t, err)
	assert.NoError(t, w.Create(ctx, got))
}

func TestHostCatalog_Delete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
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

	t.Run("delete-project", func(t *testing.T) {
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		plg := plugin.TestPlugin(t, conn, "deletescope")
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
		plg := plugin.TestPlugin(t, conn, "deleteplugin")
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

func TestHostCatalog_SecretsHmac(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, prj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	plg := plugin.TestPlugin(t, conn, "testplugin")
	cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())

	// stableValue checks that HMACing the same value returns the same result.
	// The first time it's called to match it will be empty and thus assign the
	// expected value; the second time it will assert that value.
	var stableValue string
	tests := []struct {
		name             string
		hcFn             func() *HostCatalog
		hmacWrapper      wrapping.Wrapper
		emptyHmac        bool
		matchStableValue bool
		wantHmacErrMatch *errors.Template
	}{
		{
			name: "valid-empty-secrets",
			hcFn: func() *HostCatalog {
				cat.Secrets = nil
				cat.SecretsHmac = []byte("foobar")
				return cat
			},
			emptyHmac:   true,
			hmacWrapper: databaseWrapper,
		},
		{
			name: "valid",
			hcFn: func() *HostCatalog {
				cat.Secrets = mustStruct(map[string]any{"foo": "bar"})
				cat.SecretsHmac = nil
				return cat
			},
			hmacWrapper:      databaseWrapper,
			matchStableValue: true,
		},
		{
			name: "valid-different-val",
			hcFn: func() *HostCatalog {
				cat.Secrets = mustStruct(map[string]any{"zip": "zap"})
				cat.SecretsHmac = nil
				return cat
			},
			hmacWrapper: databaseWrapper,
		},
		{
			name: "valid-original-val",
			hcFn: func() *HostCatalog {
				cat.Secrets = mustStruct(map[string]any{"foo": "bar"})
				cat.SecretsHmac = nil
				return cat
			},
			hmacWrapper:      databaseWrapper,
			matchStableValue: true,
		},
		{
			name: "hmac-missing-wrapper",
			hcFn: func() *HostCatalog {
				cat.Secrets = mustStruct(map[string]any{"foo": "bar"})
				cat.SecretsHmac = []byte("foobar")
				return cat
			},
			wantHmacErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "hmac-bad-wrapper",
			hcFn: func() *HostCatalog {
				cat.Secrets = mustStruct(map[string]any{"foo": "bar"})
				cat.SecretsHmac = nil
				return cat
			},
			hmacWrapper:      &aead.Wrapper{},
			wantHmacErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			hmacCat := tt.hcFn().clone()
			err = hmacCat.hmacSecrets(ctx, tt.hmacWrapper)
			if tt.wantHmacErrMatch != nil {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.emptyHmac {
				assert.Empty(hmacCat.SecretsHmac)
				stableValue = ""
				return
			}
			assert.NotEmpty(hmacCat.SecretsHmac)
			if tt.matchStableValue {
				if stableValue == "" {
					stableValue = base58.Encode(hmacCat.SecretsHmac)
				} else {
					assert.Equal(stableValue, base58.Encode(hmacCat.SecretsHmac))
				}
			}
		})
	}
}

func TestCatalogAgg(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, db.TestWrapper(t)))
	plg := plugin.TestPlugin(t, conn, "test")
	hc := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())

	ca := catalogAgg{}
	ca.PublicId = hc.GetPublicId()
	require.NoError(t, rw.LookupByPublicId(ctx, &ca))

	outHc, _ := ca.toCatalogAndPersisted()
	require.NotNil(t, outHc)
	require.Empty(t, cmp.Diff(hc, outHc, protocmp.Transform()))

	require.NotNil(t, ca.plugin())
	require.Empty(t, cmp.Diff(plg, ca.plugin(), protocmp.Transform()))
}
