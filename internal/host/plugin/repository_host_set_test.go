// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/patchstruct"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestRepository_CreateSet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := plugin.TestPlugin(t, conn, "create")
	unimplementedPlugin := plugin.TestPlugin(t, conn, "unimplemented")

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	unimplementedPluginCatalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	attrs := []byte{}

	const normalizeToSliceKey = "normalize_to_slice"

	tests := []struct {
		name             string
		in               *HostSet
		opts             []Option
		want             *HostSet
		wantPluginCalled bool
		wantIsErr        errors.Code
	}{
		{
			name:      "nil-HostSet",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name:      "nil-embedded-HostSet",
			in:        &HostSet{},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-catalog-id",
			in: &HostSet{
				HostSet: &store.HostSet{
					Attributes: attrs,
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  catalog.PublicId,
					PublicId:   "abcd_OOOOOOOOOO",
					Attributes: attrs,
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-attribte",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId: catalog.PublicId,
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-sync-interval-too-negative",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:           catalog.PublicId,
					SyncIntervalSeconds: -99,
					Attributes:          attrs,
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  catalog.PublicId,
					Attributes: attrs,
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  catalog.PublicId,
					Attributes: attrs,
				},
			},
			wantPluginCalled: true,
		},
		{
			name: "valid-preferred-endpoints",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  catalog.PublicId,
					Attributes: attrs,
				},
				PreferredEndpoints: []string{"cidr:1.2.3.4/32", "dns:a.b.c"},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  catalog.PublicId,
					Attributes: attrs,
				},
				PreferredEndpoints: []string{"cidr:1.2.3.4/32", "dns:a.b.c"},
			},
			wantPluginCalled: true,
		},
		{
			name: "valid-with-name",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  catalog.PublicId,
					Name:       "test-name-repo",
					Attributes: attrs,
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  catalog.PublicId,
					Name:       "test-name-repo",
					Attributes: attrs,
				},
			},
			wantPluginCalled: true,
		},
		{
			name: "valid-sync-interval-disabled",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:           catalog.PublicId,
					SyncIntervalSeconds: -1,
					Attributes:          attrs,
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:           catalog.PublicId,
					SyncIntervalSeconds: -1,
					Attributes:          attrs,
				},
			},
			wantPluginCalled: true,
		},
		{
			name: "valid-sync-interval-positive",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:           catalog.PublicId,
					SyncIntervalSeconds: 60,
					Attributes:          attrs,
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:           catalog.PublicId,
					SyncIntervalSeconds: 60,
					Attributes:          attrs,
				},
			},
			wantPluginCalled: true,
		},
		{
			name: "valid-unimplemented-plugin",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  unimplementedPluginCatalog.PublicId,
					Name:       "valid-unimplemented-plugin",
					Attributes: attrs,
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:  unimplementedPluginCatalog.PublicId,
					Name:       "valid-unimplemented-plugin",
					Attributes: attrs,
				},
			},
			wantPluginCalled: true,
		},
		{
			name: "valid-with-description",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:   catalog.PublicId,
					Description: ("test-description-repo"),
					Attributes:  attrs,
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:   catalog.PublicId,
					Description: ("test-description-repo"),
					Attributes:  attrs,
				},
			},
			wantPluginCalled: true,
		},
		{
			name: "valid-with-custom-attributes",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:   catalog.PublicId,
					Description: ("test-description-repo"),
					Attributes: func() []byte {
						st, err := structpb.NewStruct(map[string]any{
							"k1":                nil,
							"removed":           nil,
							normalizeToSliceKey: "normalizeme",
						})
						require.NoError(t, err)
						b, err := proto.Marshal(st)
						require.NoError(t, err)
						return b
					}(),
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:   catalog.PublicId,
					Description: ("test-description-repo"),
					Attributes: func() []byte {
						b, err := proto.Marshal(&structpb.Struct{Fields: map[string]*structpb.Value{
							normalizeToSliceKey: structpb.NewListValue(
								&structpb.ListValue{
									Values: []*structpb.Value{
										structpb.NewStringValue("normalizeme"),
									},
								}),
						}})
						require.NoError(t, err)
						return b
					}(),
				},
			},
			wantPluginCalled: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var origPluginAttrs, pluginReceivedAttrs *structpb.Struct
			if tt.in != nil && tt.in.HostSet != nil && len(tt.in.Attributes) > 0 {
				origPluginAttrs = new(structpb.Struct)
				require.NoError(proto.Unmarshal(tt.in.Attributes, origPluginAttrs))
			}
			var pluginCalled bool
			plgm := map[string]plgpb.HostPluginServiceClient{
				plg.GetPublicId(): loopback.NewWrappingPluginHostClient(loopback.TestPluginHostServer{
					NormalizeSetDataFn: func(_ context.Context, req *plgpb.NormalizeSetDataRequest) (*plgpb.NormalizeSetDataResponse, error) {
						if req.Attributes == nil {
							return new(plgpb.NormalizeSetDataResponse), nil
						}
						var attrs struct {
							NormalizeToSlice string `mapstructure:"normalize_to_slice"`
						}
						require.NoError(mapstructure.Decode(req.Attributes.AsMap(), &attrs))
						if attrs.NormalizeToSlice == "" {
							return new(plgpb.NormalizeSetDataResponse), nil
						}
						retAttrs := proto.Clone(req.Attributes).(*structpb.Struct)
						retAttrs.Fields[normalizeToSliceKey] = structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{structpb.NewStringValue(attrs.NormalizeToSlice)},
						})
						require.NotNil(req.GetPlugin())
						return &plgpb.NormalizeSetDataResponse{Attributes: retAttrs}, nil
					},
					OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
						pluginCalled = true
						pluginReceivedAttrs = req.GetSet().GetAttributes()
						require.NotNil(req.GetCatalog().GetPlugin())
						return &plgpb.OnCreateSetResponse{}, nil
					},
				}),
				unimplementedPlugin.GetPublicId(): loopback.NewWrappingPluginHostClient(loopback.TestPluginHostServer{OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
					pluginCalled = true
					pluginReceivedAttrs = req.GetSet().GetAttributes()
					return plgpb.UnimplementedHostPluginServiceServer{}.OnCreateSet(ctx, req)
				}}),
			}
			repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
			require.NoError(err)
			require.NotNil(repo)
			got, plgInfo, err := repo.CreateSet(ctx, prj.GetPublicId(), tt.in, tt.opts...)
			assert.Equal(tt.wantPluginCalled, pluginCalled)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assert.True(strings.HasPrefix(got.GetPublicId(), globals.PluginHostSetPrefix))
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.GetName())
			assert.Equal(tt.want.Description, got.GetDescription())
			assert.Equal(got.GetCreateTime(), got.GetUpdateTime())
			assert.Equal(string(tt.want.GetAttributes()), string(got.GetAttributes()))

			if origPluginAttrs != nil {
				if normalizeVal := origPluginAttrs.Fields[normalizeToSliceKey]; normalizeVal != nil {
					gotVal := pluginReceivedAttrs.Fields[normalizeToSliceKey]
					require.NotNil(gotVal)
					listVal := gotVal.GetListValue()
					require.NotNil(listVal)
					require.Len(listVal.Values, 1)
					assert.Equal(normalizeVal.GetStringValue(), listVal.Values[0].GetStringValue())
					origPluginAttrs.Fields[normalizeToSliceKey] = structpb.NewListValue(listVal)
					tt.want.Attributes, err = proto.Marshal(origPluginAttrs)
					require.NoError(err)
					tt.want.Attributes, err = patchstruct.PatchBytes([]byte{}, tt.want.Attributes)
					require.NoError(err)
				}
			}

			wantedPluginAttributes := &structpb.Struct{}
			require.NoError(proto.Unmarshal(tt.want.Attributes, wantedPluginAttributes))
			assert.Empty(cmp.Diff(wantedPluginAttributes, pluginReceivedAttrs, protocmp.Transform()))
			assert.Empty(cmp.Diff(plgInfo, plg, protocmp.Transform()))

			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		var pluginCalled bool
		plgm := map[string]plgpb.HostPluginServiceClient{
			plg.GetPublicId(): loopback.NewWrappingPluginHostClient(loopback.TestPluginHostServer{OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
				pluginCalled = true
				return &plgpb.OnCreateSetResponse{}, nil
			}}),
		}
		repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iamRepo)
		catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())

		in := &HostSet{
			HostSet: &store.HostSet{
				CatalogId:  catalog.PublicId,
				Name:       "test-name-repo",
				Attributes: []byte{},
			},
		}

		got, _, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assert.True(pluginCalled)
		assert.True(strings.HasPrefix(got.GetPublicId(), globals.PluginHostSetPrefix))
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.GetName())
		assert.Equal(in.Description, got.GetDescription())
		assert.Equal(got.GetCreateTime(), got.GetUpdateTime())

		// reset pluginCalled so we can see the duplicate name causes the plugin
		// to not get called.
		pluginCalled = false
		got2, _, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in)
		assert.False(pluginCalled)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-catalogs", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		var pluginCalled bool
		plgm := map[string]plgpb.HostPluginServiceClient{
			plg.GetPublicId(): loopback.NewWrappingPluginHostClient(loopback.TestPluginHostServer{OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
				pluginCalled = true
				return &plgpb.OnCreateSetResponse{}, nil
			}}),
		}
		repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iamRepo)
		catalogA := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
		catalogB := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())

		in := &HostSet{
			HostSet: &store.HostSet{
				Name:       "test-name-repo",
				Attributes: []byte{},
			},
		}
		in2 := in.clone()

		in.CatalogId = catalogA.PublicId
		// reset pluginCalled so we can see that the plugin is called during this
		// createSet call
		pluginCalled = false
		got, _, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in)
		assert.True(pluginCalled)
		require.NoError(err)
		require.NotNil(got)
		assert.True(strings.HasPrefix(got.GetPublicId(), globals.PluginHostSetPrefix))
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.GetName())
		assert.Equal(in.Description, got.GetDescription())
		assert.Equal(got.GetCreateTime(), got.GetUpdateTime())

		in2.CatalogId = catalogB.PublicId
		// reset pluginCalled so we can see that the plugin is called during this
		// createSet call
		pluginCalled = false
		got2, _, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assert.True(pluginCalled)
		assert.True(strings.HasPrefix(got.GetPublicId(), globals.PluginHostSetPrefix))
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.GetName())
		assert.Equal(in2.Description, got2.GetDescription())
		assert.Equal(got2.GetCreateTime(), got2.GetUpdateTime())
	})
}

func TestRepository_UpdateSet(t *testing.T) {
	ctx := context.Background()
	dbConn, _ := db.TestSetup(t, "postgres")
	dbRW := db.New(dbConn)
	dbWrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, dbConn, dbWrapper)
	dbKmsCache := kms.TestKms(t, dbConn, dbWrapper)
	_, projectScope := iam.TestScopes(t, iam.TestRepo(t, dbConn, dbWrapper))

	testPlugin := plugin.TestPlugin(t, dbConn, "test")
	dummyPluginMap := map[string]plgpb.HostPluginServiceClient{
		testPlugin.GetPublicId(): &loopback.WrappingPluginHostClient{Server: &plgpb.UnimplementedHostPluginServiceServer{}},
	}

	// Set up a test catalog and the secrets for it
	testCatalog := TestCatalog(t, dbConn, projectScope.PublicId, testPlugin.GetPublicId())
	testCatalogSecret, err := newHostCatalogSecret(ctx, testCatalog.GetPublicId(), mustStruct(map[string]any{
		"one": "two",
	}))
	require.NoError(t, err)
	scopeWrapper, err := dbKmsCache.GetWrapper(ctx, testCatalog.GetProjectId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	require.NoError(t, testCatalogSecret.encrypt(ctx, scopeWrapper))
	err = dbRW.Create(ctx, testCatalogSecret)
	require.NoError(t, err)

	const normalizeToSliceKey = "normalize_to_slice"

	// Create a test duplicate set. We don't use this set, it just
	// exists to ensure that we can test for conflicts when setting
	// the name.
	const testDuplicateSetName = "duplicate-set-name"
	testDuplicateSet := TestSet(t, dbConn, dbKmsCache, sched, testCatalog, dummyPluginMap)
	testDuplicateSet.Name = testDuplicateSetName
	setsUpdated, err := dbRW.Update(ctx, testDuplicateSet, []string{"name"}, []string{})
	require.NoError(t, err)
	require.Equal(t, 1, setsUpdated)

	// Define some helpers here to make the test table more readable.
	type changeHostSetFunc func(s *HostSet) *HostSet

	changeSetToNil := func() changeHostSetFunc {
		return func(_ *HostSet) *HostSet {
			return nil
		}
	}

	changeEmbeddedSetToNil := func() changeHostSetFunc {
		return func(s *HostSet) *HostSet {
			s.HostSet = nil
			return s
		}
	}

	changePublicId := func(v string) changeHostSetFunc {
		return func(s *HostSet) *HostSet {
			s.PublicId = v
			return s
		}
	}

	changeName := func(v string) changeHostSetFunc {
		return func(s *HostSet) *HostSet {
			s.Name = v
			return s
		}
	}

	changeDescription := func(s string) changeHostSetFunc {
		return func(c *HostSet) *HostSet {
			c.Description = s
			return c
		}
	}

	changeSyncInterval := func(s int32) changeHostSetFunc {
		return func(c *HostSet) *HostSet {
			c.SyncIntervalSeconds = s
			return c
		}
	}

	changePreferredEndpoints := func(s []string) changeHostSetFunc {
		return func(c *HostSet) *HostSet {
			c.PreferredEndpoints = s
			return c
		}
	}

	changeAttributes := func(m map[string]any) changeHostSetFunc {
		return func(c *HostSet) *HostSet {
			c.Attributes = mustMarshal(m)
			return c
		}
	}

	changeAttributesNil := func() changeHostSetFunc {
		return func(c *HostSet) *HostSet {
			c.Attributes = nil
			return c
		}
	}

	// Define some checks that will be used in the below tests. Some of
	// these are re-used, so we define them here. Most of these are
	// assertions and no particular one is non-fatal in that they will
	// stop execution. Note that these are executed after wantIsErr, so
	// if that is set in an individual table test, these will not be
	// executed.
	//
	// Note that we define some state here, similar to how we
	// previously defined gotOnUpdateCatalogRequest above next the
	// plugin map.
	type checkHostSetFunc func(t *testing.T, got *HostSet)

	checkVersion := func(want uint32) checkHostSetFunc {
		return func(t *testing.T, got *HostSet) {
			t.Helper()
			assert.Equal(t, want, got.Version, "checkVersion")
		}
	}

	checkName := func(want string) checkHostSetFunc {
		return func(t *testing.T, got *HostSet) {
			t.Helper()
			assert.Equal(t, want, got.Name, "checkName")
		}
	}

	checkDescription := func(want string) checkHostSetFunc {
		return func(t *testing.T, got *HostSet) {
			t.Helper()
			assert.Equal(t, want, got.Description, "checkDescription")
		}
	}

	checkPreferredEndpoints := func(want []string) checkHostSetFunc {
		return func(t *testing.T, got *HostSet) {
			t.Helper()
			assert.Equal(t, want, got.PreferredEndpoints, "checkPreferredEndpoints")
		}
	}

	checkAttributes := func(want map[string]any) checkHostSetFunc {
		return func(t *testing.T, got *HostSet) {
			t.Helper()
			st := &structpb.Struct{}
			require.NoError(t, proto.Unmarshal(got.Attributes, st))
			assert.Empty(t, cmp.Diff(mustStruct(want), st, protocmp.Transform()))
		}
	}

	checkSyncInterval := func(want int32) checkHostSetFunc {
		return func(t *testing.T, got *HostSet) {
			t.Helper()
			assert.Equal(t, want, got.SyncIntervalSeconds, "checkSyncInterval")
		}
	}

	checkNeedSync := func(want bool) checkHostSetFunc {
		return func(t *testing.T, got *HostSet) {
			t.Helper()
			assert.Equal(t, want, got.NeedSync, "checkNeedSync")
		}
	}

	checkVerifySetOplog := func(op oplog.OpType) checkHostSetFunc {
		return func(t *testing.T, got *HostSet) {
			t.Helper()
			assert.NoError(t,
				db.TestVerifyOplog(
					t,
					dbRW,
					got.PublicId,
					db.WithOperation(op),
					db.WithCreateNotBefore(10*time.Second),
				),
			)
		}
	}

	type checkPluginReqFunc func(t *testing.T, got *plgpb.OnUpdateSetRequest)

	checkUpdateSetRequestCurrentNameNil := func() checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Nil(t, got.CurrentSet.Name, "checkUpdateSetRequestCurrentNameNil")
		}
	}

	checkUpdateSetRequestNewName := func(want string) checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Equal(t, wrapperspb.String(want), got.NewSet.Name, "checkUpdateSetRequestNewName")
		}
	}

	checkUpdateSetRequestNewNameNil := func() checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Nil(t, got.NewSet.Name, "checkUpdateSetRequestNewNameNil")
		}
	}

	checkUpdateSetRequestCurrentDescriptionNil := func() checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Nil(t, got.CurrentSet.Description, "checkUpdateSetRequestCurrentDescriptionNil")
		}
	}

	checkUpdateSetRequestNewDescription := func(want string) checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Equal(t, wrapperspb.String(want), got.NewSet.Description, "checkUpdateSetRequestNewDescription")
		}
	}

	checkUpdateSetRequestNewDescriptionNil := func() checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Nil(t, got.NewSet.Description, "checkUpdateSetRequestNewDescriptionNil")
		}
	}

	checkUpdateSetRequestCurrentPreferredEndpoints := func(want []string) checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Equal(t, want, got.CurrentSet.PreferredEndpoints, "checkUpdateSetRequestCurrentPreferredEndpoints")
		}
	}

	checkUpdateSetRequestNewPreferredEndpoints := func(want []string) checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Equal(t, want, got.NewSet.PreferredEndpoints, "checkUpdateSetRequestNewPreferredEndpoints")
		}
	}

	checkUpdateSetRequestNewPreferredEndpointsNil := func() checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Nil(t, got.NewSet.PreferredEndpoints, "checkUpdateSetRequestNewPreferredEndpointsNil")
		}
	}

	checkUpdateSetRequestCurrentAttributes := func(want map[string]any) checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Empty(t, cmp.Diff(mustStruct(want), got.CurrentSet.GetAttributes(), protocmp.Transform()), "checkUpdateSetRequestCurrentAttributes")
		}
	}

	checkUpdateSetRequestNewAttributes := func(want map[string]any) checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Empty(t, cmp.Diff(mustStruct(want), got.NewSet.GetAttributes(), protocmp.Transform()), "checkUpdateSetRequestNewAttributes")
		}
	}

	checkUpdateSetRequestPersistedSecrets := func(want map[string]any) checkPluginReqFunc {
		return func(t *testing.T, got *plgpb.OnUpdateSetRequest) {
			t.Helper()
			assert.Empty(t, cmp.Diff(mustStruct(want), got.Persisted.Secrets, protocmp.Transform()), "checkUpdateSetRequestPersistedSecrets")
		}
	}

	// Finally define a function for bringing the test subject host
	// set.
	setupBareHostSet := func(t *testing.T, ctx context.Context) (*HostSet, []*Host) {
		t.Helper()
		set := TestSet(
			t,
			dbConn,
			dbKmsCache,
			sched,
			testCatalog,
			dummyPluginMap,
		)

		t.Cleanup(func() {
			t.Helper()
			assert := assert.New(t)
			n, err := dbRW.Delete(ctx, set)
			assert.NoError(err)
			assert.Equal(1, n)
		})

		return set, nil
	}

	// Create a host that will be verified as belonging to the created set below.
	testHostExternIdPrefix := "test-host-external-id"
	testHosts := make([]*Host, 3)
	for i := 0; i <= 2; i++ {
		testHosts[i] = TestHost(t, dbConn, testCatalog.PublicId, fmt.Sprintf("%s-%d", testHostExternIdPrefix, i))
	}

	// Finally define a function for bringing the test subject host
	// set.
	setupHostSet := func(t *testing.T, ctx context.Context) (*HostSet, []*Host) {
		t.Helper()
		require := require.New(t)

		set := TestSet(
			t,
			dbConn,
			dbKmsCache,
			sched,
			testCatalog,
			dummyPluginMap,
			WithPreferredEndpoints([]string{"cidr:192.168.0.0/24", "cidr:192.168.1.0/24", "cidr:172.16.0.0/12"}),
		)
		// Set some (default) attributes on our test set
		set.Attributes = mustMarshal(map[string]any{
			"foo": "bar",
		})

		// Set some fake sync detail to the set.
		set.LastSyncTime = timestamp.New(time.Now())
		set.NeedSync = false

		numSetsUpdated, err := dbRW.Update(ctx, set, []string{"attributes", "LastSyncTime", "NeedSync"}, []string{})
		require.NoError(err)
		require.Equal(1, numSetsUpdated)

		// Add some hosts to the host set.
		TestSetMembers(t, dbConn, set.PublicId, testHosts)

		t.Cleanup(func() {
			t.Helper()
			assert := assert.New(t)
			n, err := dbRW.Delete(ctx, set)
			assert.NoError(err)
			assert.Equal(1, n)
		})

		return set, testHosts
	}

	tests := []struct {
		name                    string
		startingSet             func(*testing.T, context.Context) (*HostSet, []*Host)
		withProjectId           *string
		withEmptyPluginMap      bool
		withPluginError         error
		changeFuncs             []changeHostSetFunc
		version                 uint32
		fieldMask               []string
		wantCheckSetFuncs       []checkHostSetFunc
		wantCheckPluginReqFuncs []checkPluginReqFunc
		wantIsErr               errors.Code
	}{
		{
			name:        "nil set",
			startingSet: setupBareHostSet,
			changeFuncs: []changeHostSetFunc{changeSetToNil()},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "nil embedded set",
			startingSet: setupBareHostSet,
			changeFuncs: []changeHostSetFunc{changeEmbeddedSetToNil()},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "missing public id",
			startingSet: setupBareHostSet,
			changeFuncs: []changeHostSetFunc{changePublicId("")},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:          "missing project id",
			startingSet:   setupBareHostSet,
			withProjectId: func() *string { a := ""; return &a }(),
			wantIsErr:     errors.InvalidParameter,
		},
		{
			name:        "empty field mask",
			startingSet: setupBareHostSet,
			fieldMask:   nil, // Should be testing on len
			wantIsErr:   errors.EmptyFieldMask,
		},
		{
			name:        "bad set id",
			startingSet: setupBareHostSet,
			changeFuncs: []changeHostSetFunc{changePublicId("badid")},
			fieldMask:   []string{"name"},
			wantIsErr:   errors.RecordNotFound,
		},
		{
			name:        "version mismatch",
			startingSet: setupBareHostSet,
			changeFuncs: []changeHostSetFunc{changeName("foo")},
			version:     4,
			fieldMask:   []string{"name"},
			wantIsErr:   errors.VersionMismatch,
		},
		{
			name:          "mismatched project id to catalog project",
			startingSet:   setupBareHostSet,
			withProjectId: func() *string { a := "badid"; return &a }(),
			fieldMask:     []string{"name"},
			wantIsErr:     errors.InvalidParameter,
		},
		{
			name:               "plugin lookup error",
			startingSet:        setupBareHostSet,
			withEmptyPluginMap: true,
			fieldMask:          []string{"name"},
			wantIsErr:          errors.Internal,
		},
		{
			name:            "plugin invocation error",
			startingSet:     setupBareHostSet,
			withPluginError: errors.New(context.Background(), errors.Internal, "TestRepository_UpdateSet/plugin_invocation_error", "test plugin error"),
			fieldMask:       []string{"name"},
			wantIsErr:       errors.Internal,
		},
		{
			name:        "update name (duplicate)",
			startingSet: setupBareHostSet,
			changeFuncs: []changeHostSetFunc{changeName(testDuplicateSetName)},
			fieldMask:   []string{"name"},
			wantIsErr:   errors.NotUnique,
		},
		{
			name:        "update name",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changeName("foo")},
			fieldMask:   []string{"name"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentNameNil(),
				checkUpdateSetRequestNewName("foo"),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(3),
				checkName("foo"),
				checkNeedSync(false),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update name to same",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changeName("")},
			fieldMask:   []string{"name"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentNameNil(),
				checkUpdateSetRequestNewNameNil(),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(2), // Version remains same even though row is updated
				checkName(""),
				checkNeedSync(false),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update description",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changeDescription("foo")},
			fieldMask:   []string{"description"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentDescriptionNil(),
				checkUpdateSetRequestNewDescription("foo"),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(3),
				checkDescription("foo"),
				checkNeedSync(false),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update description to same",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changeDescription("")},
			fieldMask:   []string{"description"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentDescriptionNil(),
				checkUpdateSetRequestNewDescriptionNil(),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(2), // Version remains same even though row is updated
				checkDescription(""),
				checkNeedSync(false),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "set sync interval",
			startingSet: setupBareHostSet,
			changeFuncs: []changeHostSetFunc{changeSyncInterval(42)},
			fieldMask:   []string{"SyncIntervalSeconds"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(2),
				checkNeedSync(true),
				checkSyncInterval(42),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "add preferred endpoints",
			startingSet: setupBareHostSet,
			changeFuncs: []changeHostSetFunc{changePreferredEndpoints([]string{"cidr:10.0.0.0/24"})},
			fieldMask:   []string{"PreferredEndpoints"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentPreferredEndpoints(nil),
				checkUpdateSetRequestNewPreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(2),
				checkPreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				checkNeedSync(true),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update preferred endpoints",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changePreferredEndpoints([]string{"cidr:10.0.0.0/24"})},
			fieldMask:   []string{"PreferredEndpoints"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentPreferredEndpoints([]string{"cidr:192.168.0.0/24", "cidr:192.168.1.0/24", "cidr:172.16.0.0/12"}),
				checkUpdateSetRequestNewPreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(3),
				checkPreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				checkNeedSync(false),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "clear preferred endpoints",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changePreferredEndpoints(nil)},
			fieldMask:   []string{"PreferredEndpoints"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentPreferredEndpoints([]string{"cidr:192.168.0.0/24", "cidr:192.168.1.0/24", "cidr:172.16.0.0/12"}),
				checkUpdateSetRequestNewPreferredEndpointsNil(),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(3),
				checkPreferredEndpoints(nil),
				checkNeedSync(false),
			},
		},
		{
			name:        "update attributes (add)",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changeAttributes(map[string]any{
				"baz": "qux",
			})},
			fieldMask: []string{"attributes"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentAttributes(map[string]any{
					"foo": "bar",
				}),
				checkUpdateSetRequestNewAttributes(map[string]any{
					"foo": "bar",
					"baz": "qux",
				}),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(3),
				checkAttributes(map[string]any{
					"foo": "bar",
					"baz": "qux",
				}),
				checkNeedSync(true),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update attributes (overwrite)",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changeAttributes(map[string]any{
				"foo":               "baz",
				normalizeToSliceKey: "normalizeme",
			})},
			fieldMask: []string{"attributes"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentAttributes(map[string]any{
					"foo": "bar",
				}),
				checkUpdateSetRequestNewAttributes(map[string]any{
					"foo":               "baz",
					normalizeToSliceKey: []any{"normalizeme"},
				}),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(3),
				checkAttributes(map[string]any{
					"foo":               "baz",
					normalizeToSliceKey: []any{"normalizeme"},
				}),
				checkNeedSync(true),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update attributes (null)",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changeAttributes(map[string]any{
				"foo": nil,
			})},
			fieldMask: []string{"attributes"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentAttributes(map[string]any{
					"foo": "bar",
				}),
				checkUpdateSetRequestNewAttributes(map[string]any{}),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(3),
				checkAttributes(map[string]any{}),
				checkNeedSync(true),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update attributes (full null)",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changeAttributesNil()},
			fieldMask:   []string{"attributes"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentAttributes(map[string]any{
					"foo": "bar",
				}),
				checkUpdateSetRequestNewAttributes(map[string]any{}),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(3),
				checkAttributes(map[string]any{}),
				checkNeedSync(true),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update attributes (combined)",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{changeAttributes(map[string]any{
				"a":   "b",
				"foo": "baz",
			})},
			fieldMask: []string{"attributes.a", "attributes.foo"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentAttributes(map[string]any{
					"foo": "bar",
				}),
				checkUpdateSetRequestNewAttributes(map[string]any{
					"a":   "b",
					"foo": "baz",
				}),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(3),
				checkAttributes(map[string]any{
					"a":   "b",
					"foo": "baz",
				}),
				checkNeedSync(true),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update name and preferred endpoints",
			startingSet: setupHostSet,
			changeFuncs: []changeHostSetFunc{
				changePreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				changeName("foo"),
			},
			fieldMask: []string{"name", "PreferredEndpoints"},
			wantCheckPluginReqFuncs: []checkPluginReqFunc{
				checkUpdateSetRequestCurrentNameNil(),
				checkUpdateSetRequestNewName("foo"),
				checkUpdateSetRequestCurrentPreferredEndpoints([]string{"cidr:192.168.0.0/24", "cidr:192.168.1.0/24", "cidr:172.16.0.0/12"}),
				checkUpdateSetRequestNewPreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				checkUpdateSetRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
			},
			wantCheckSetFuncs: []checkHostSetFunc{
				checkVersion(3),
				checkName("foo"),
				checkPreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				checkNeedSync(false),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			// Define a plugin "manager", basically just a map with a mock
			// plugin in it.  This also includes functionality to capture the
			// state, and set an error and the returned secrets to nil. Note
			// that the way that this is set up means that the tests cannot run
			// in parallel, but there could be other factors affecting that as
			// well.
			var gotOnUpdateCallCount int
			testPluginMap := map[string]plgpb.HostPluginServiceClient{
				testPlugin.GetPublicId(): &loopback.WrappingPluginHostClient{
					Server: &loopback.TestPluginHostServer{
						NormalizeSetDataFn: func(_ context.Context, req *plgpb.NormalizeSetDataRequest) (*plgpb.NormalizeSetDataResponse, error) {
							if req.Attributes == nil {
								return new(plgpb.NormalizeSetDataResponse), nil
							}
							var attrs struct {
								NormalizeToSlice string `mapstructure:"normalize_to_slice"`
							}
							require.NoError(mapstructure.Decode(req.Attributes.AsMap(), &attrs))
							if attrs.NormalizeToSlice == "" {
								return new(plgpb.NormalizeSetDataResponse), nil
							}
							retAttrs := proto.Clone(req.Attributes).(*structpb.Struct)
							retAttrs.Fields[normalizeToSliceKey] = structpb.NewListValue(&structpb.ListValue{
								Values: []*structpb.Value{structpb.NewStringValue(attrs.NormalizeToSlice)},
							})
							require.NotNil(req.GetPlugin())
							return &plgpb.NormalizeSetDataResponse{Attributes: retAttrs}, nil
						},
						OnUpdateSetFn: func(_ context.Context, req *plgpb.OnUpdateSetRequest) (*plgpb.OnUpdateSetResponse, error) {
							gotOnUpdateCallCount++
							for _, check := range tt.wantCheckPluginReqFuncs {
								check(t, req)
							}
							require.NotNil(req.GetCatalog().GetPlugin())
							return &plgpb.OnUpdateSetResponse{}, tt.withPluginError
						},
					},
				},
			}

			origSet, wantedHosts := tt.startingSet(t, ctx)

			pluginMap := testPluginMap
			if tt.withEmptyPluginMap {
				pluginMap = make(map[string]plgpb.HostPluginServiceClient)
			}
			repo, err := NewRepository(ctx, dbRW, dbRW, dbKmsCache, sched, pluginMap)
			require.NoError(err)
			require.NotNil(repo)

			workingSet := origSet.clone()
			for _, cf := range tt.changeFuncs {
				workingSet = cf(workingSet)
			}

			projectId := testCatalog.ProjectId
			if tt.withProjectId != nil {
				projectId = *tt.withProjectId
			}

			version := origSet.Version
			if tt.version != 0 {
				version = tt.version
			}

			gotUpdatedSet, gotHosts, gotPlugin, gotNumUpdated, err := repo.UpdateSet(ctx, projectId, workingSet, version, tt.fieldMask)
			t.Cleanup(func() { gotOnUpdateCallCount = 0 })
			if tt.wantIsErr != 0 {
				require.Equal(db.NoRowsAffected, gotNumUpdated)
				require.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			require.Equal(1, gotOnUpdateCallCount)
			assert.Equal(1, gotNumUpdated)

			// Quick assertion that the set is not nil and that the plugin
			// ID in the catalog referenced by the set matches the plugin
			// ID in the returned plugin.
			require.NotNil(gotUpdatedSet)
			require.NotNil(gotPlugin)
			assert.Equal(testCatalog.PublicId, gotUpdatedSet.CatalogId)
			assert.Equal(testCatalog.PluginId, gotPlugin.PublicId)

			// Also assert that the hosts returned by the request are the ones that belong to the set
			wantHostMap := make(map[string]string, len(wantedHosts))
			for _, h := range wantedHosts {
				wantHostMap[h.PublicId] = h.ExternalId
			}
			gotHostMap := make(map[string]string, len(gotHosts))
			for _, h := range gotHosts {
				gotHostMap[h.PublicId] = h.ExternalId
			}
			assert.Equal(wantHostMap, gotHostMap)

			// Perform checks
			for _, check := range tt.wantCheckSetFuncs {
				check(t, gotUpdatedSet)
			}

			gotLookupSet, _, err := repo.LookupSet(ctx, workingSet.GetPublicId())
			assert.NoError(err)
			assert.Empty(cmp.Diff(gotUpdatedSet, gotLookupSet, protocmp.Transform()))
		})
	}

	t.Run("Unset Empty PreferredEndpoint", func(t *testing.T) {
		var gotOnUpdateCallCount int
		testPluginMap := map[string]plgpb.HostPluginServiceClient{
			testPlugin.GetPublicId(): &loopback.WrappingPluginHostClient{
				Server: &loopback.TestPluginHostServer{
					OnUpdateSetFn: func(_ context.Context, req *plgpb.OnUpdateSetRequest) (*plgpb.OnUpdateSetResponse, error) {
						gotOnUpdateCallCount++
						for _, check := range []checkPluginReqFunc{
							checkUpdateSetRequestCurrentPreferredEndpoints(nil),
							checkUpdateSetRequestNewPreferredEndpointsNil(),
							checkUpdateSetRequestPersistedSecrets(map[string]any{
								"one": "two",
							}),
						} {
							check(t, req)
						}
						return &plgpb.OnUpdateSetResponse{}, nil
					},
				},
			},
		}

		origSet, _ := setupBareHostSet(t, ctx)

		pluginMap := testPluginMap
		repo, err := NewRepository(ctx, dbRW, dbRW, dbKmsCache, sched, pluginMap)
		require.NoError(t, err)
		require.NotNil(t, repo)

		workingSet := origSet.clone()
		workingSet = changePreferredEndpoints(nil)(workingSet)

		gotUpdatedSet, _, _, gotNumUpdated, err := repo.UpdateSet(ctx, testCatalog.ProjectId, workingSet, origSet.Version, []string{"PreferredEndpoints"})
		t.Cleanup(func() { gotOnUpdateCallCount = 0 })

		require.NoError(t, err)
		require.Equal(t, 1, gotOnUpdateCallCount)
		assert.Equal(t, 0, gotNumUpdated)
		assert.Empty(t, cmp.Diff(gotUpdatedSet, origSet, protocmp.Transform()))
	})
}

func TestRepository_UpdateSet_UnsetEmptyPreferredEndpoint(t *testing.T) {
}

func TestRepository_LookupSet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := plugin.TestPlugin(t, conn, "lookup")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	hostSet := TestSet(t, conn, kms, sched, catalog, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginHostServer{
			ListHostsFn: func(ctx context.Context, req *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error) {
				require.NotEmpty(t, req.GetSets())
				require.NotNil(t, req.GetCatalog())
				return &plgpb.ListHostsResponse{}, nil
			},
		}),
	}, WithSyncIntervalSeconds(5))
	hostSetId, err := newHostSetId(ctx)
	require.NoError(t, err)

	tests := []struct {
		name      string
		in        string
		want      *HostSet
		wantIsErr errors.Code
	}{
		{
			name:      "with-no-public-id",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "with-non-existing-host-set-id",
			in:   hostSetId,
		},
		{
			name: "with-existing-host-set-id",
			in:   hostSet.PublicId,
			want: hostSet,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
			assert.NoError(err)
			require.NotNil(repo)
			got, _, err := repo.LookupSet(ctx, tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			if tt.want != nil {
				assert.Empty(cmp.Diff(got, tt.want, protocmp.Transform()), "LookupSet(%q) got response %q, wanted %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRepository_Endpoints(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := plugin.TestPlugin(t, conn, "endpoints")

	hostlessCatalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	hostSet10 := TestSet(t, conn, kms, sched, catalog, plgm, WithName("hostSet10"), WithPreferredEndpoints([]string{"cidr:10.0.0.1/24"}))
	hostSet192 := TestSet(t, conn, kms, sched, catalog, plgm, WithName("hostSet192"), WithPreferredEndpoints([]string{"cidr:192.168.0.1/24"}))
	hostSet100 := TestSet(t, conn, kms, sched, catalog, plgm, WithName("hostSet100"), WithPreferredEndpoints([]string{"cidr:100.100.100.100/24"}))
	hostSetDNS := TestSet(t, conn, kms, sched, catalog, plgm, WithName("hostSetDNS"), WithPreferredEndpoints([]string{"dns:*"}))
	hostlessSet := TestSet(t, conn, kms, sched, hostlessCatalog, plgm)

	h1 := TestHost(t, conn, catalog.GetPublicId(), "test", withIpAddresses([]string{"10.0.0.5", "192.168.0.5"}), withDnsNames([]string{"example.com"}))
	TestSetMembers(t, conn, hostSet10.GetPublicId(), []*Host{h1})
	TestSetMembers(t, conn, hostSet192.GetPublicId(), []*Host{h1})
	TestSetMembers(t, conn, hostSet100.GetPublicId(), []*Host{h1})
	TestSetMembers(t, conn, hostSetDNS.GetPublicId(), []*Host{h1})

	tests := []struct {
		name      string
		setIds    []string
		want      []*host.Endpoint
		wantIsErr errors.Code
	}{
		{
			name:      "with-no-set-id",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name:   "with-set10",
			setIds: []string{hostSet10.GetPublicId()},
			want: []*host.Endpoint{
				{
					HostId: func() string {
						s, err := newHostId(ctx, catalog.GetPublicId(), "test")
						require.NoError(t, err)
						return s
					}(),
					SetId:   hostSet10.GetPublicId(),
					Address: "10.0.0.5",
				},
			},
		},
		{
			name:   "with-different-set",
			setIds: []string{hostSet192.GetPublicId()},
			want: []*host.Endpoint{
				{
					HostId: func() string {
						s, err := newHostId(ctx, catalog.GetPublicId(), "test")
						require.NoError(t, err)
						return s
					}(),
					SetId:   hostSet192.GetPublicId(),
					Address: "192.168.0.5",
				},
			},
		},
		{
			name:   "with-all-addresses-filtered-set",
			setIds: []string{hostSet100.GetPublicId()},
			want:   nil,
		},
		{
			name:   "with-no-hosts-from-plugin",
			setIds: []string{hostlessSet.GetPublicId()},
			want:   nil,
		},
		{
			name:   "with-dns-names",
			setIds: []string{hostSetDNS.GetPublicId()},
			want: []*host.Endpoint{
				{
					HostId: func() string {
						s, err := newHostId(ctx, catalog.GetPublicId(), "test")
						require.NoError(t, err)
						return s
					}(),
					SetId:   hostSetDNS.GetPublicId(),
					Address: "example.com",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.Endpoints(ctx, tt.setIds)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			if tt.want == nil {
				return
			}

			sort.Slice(tt.want, func(i, j int) bool {
				return tt.want[i].HostId < tt.want[j].HostId
			})
			sort.Slice(got, func(i, j int) bool {
				return got[i].HostId < got[j].HostId
			})
			assert.Empty(cmp.Diff(got, tt.want, protocmp.Transform()))

			for _, ep := range got {
				h := allocHost()
				h.PublicId = ep.HostId
				require.NoError(rw.LookupByPublicId(ctx, h))

				assert.Equal(ep.HostId, h.PublicId)
				// TODO: Uncomment when we have a better way to lookup host
				// with it's address
				// assert.Equal(ep.Address, h.Address)
				assert.Equal(catalog.GetPublicId(), h.GetCatalogId())
			}
		})
	}
}

func TestRepository_listSets(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := plugin.TestPlugin(t, conn, "list")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}
	catalogA := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	catalogB := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())

	hostSets := []*HostSet{
		TestSet(t, conn, kms, sched, catalogA, plgm),
		TestSet(t, conn, kms, sched, catalogA, plgm),
		TestSet(t, conn, kms, sched, catalogA, plgm),
	}

	printoutTable(t, rw)

	tests := []struct {
		name      string
		in        string
		opts      []Option
		want      []*HostSet
		wantIsErr errors.Code
	}{
		{
			name:      "with-no-catalog-id",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "Catalog-with-no-host-sets",
			in:   catalogB.PublicId,
			want: nil,
		},
		{
			name: "Catalog-with-host-sets",
			in:   catalogA.PublicId,
			want: hostSets,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
			assert.NoError(err)
			require.NotNil(repo)
			got, gotPlg, ttime, err := repo.listSets(ctx, tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *HostSet) bool { return x.PublicId < y.PublicId }),
				protocmp.Transform(),
			}
			assert.Empty(cmp.Diff(tt.want, got, opts...))
			if got != nil {
				assert.Empty(cmp.Diff(plg, gotPlg, protocmp.Transform()))
			}
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func TestRepository_listSets_Limits(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := plugin.TestPlugin(t, conn, "listlimit")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&loopback.TestPluginServer{}),
	}
	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	count := 10
	var hostSets []*HostSet
	for i := 0; i < count; i++ {
		hostSets = append(hostSets, TestSet(t, conn, kms, sched, catalog, plgm))
	}

	tests := []struct {
		name     string
		repoOpts []host.Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "With no limits",
			wantLen: count,
		},
		{
			name:     "With repo limit",
			repoOpts: []host.Option{host.WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With repo smaller than list limit",
			repoOpts: []host.Option{host.WithLimit(2)},
			listOpts: []Option{WithLimit(6)},
			wantLen:  6,
		},
		{
			name:     "With repo larger than list limit",
			repoOpts: []host.Option{host.WithLimit(6)},
			listOpts: []Option{WithLimit(2)},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, gotPlg, ttime, err := repo.listSets(ctx, hostSets[0].CatalogId, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
			assert.Empty(cmp.Diff(plg, gotPlg, protocmp.Transform()))
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func TestRepository_listSets_Pagination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	plg := plugin.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &loopback.WrappingPluginHostClient{Server: &loopback.TestPluginServer{}},
	}
	catalog := TestCatalog(t, conn, proj1.GetPublicId(), plg.GetPublicId())

	total := 5
	for i := 0; i < total; i++ {
		TestSet(t, conn, kms, sched, catalog, plgm)
	}

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
	require.NoError(t, err)

	t.Run("no-options", func(t *testing.T) {
		got, retPlg, ttime, err := repo.listSets(ctx, catalog.GetPublicId())
		require.NoError(t, err)
		assert.Equal(t, total, len(got))
		assert.Equal(t, retPlg, plg)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
	})

	t.Run("withStartPageAfter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		page1, retPlg, ttime, err := repo.listSets(
			context.Background(),
			catalog.GetPublicId(),
			WithLimit(2),
		)
		require.NoError(err)
		require.Len(page1, 2)
		assert.Equal(retPlg, plg)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page2, retPlg, ttime, err := repo.listSets(
			context.Background(),
			catalog.GetPublicId(),
			WithLimit(2),
			WithStartPageAfterItem(page1[1]),
		)
		require.NoError(err)
		require.Len(page2, 2)
		assert.Equal(retPlg, plg)
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page3, retPlg, ttime, err := repo.listSets(
			context.Background(),
			catalog.GetPublicId(),
			WithLimit(2),
			WithStartPageAfterItem(page2[1]),
		)
		require.NoError(err)
		require.Len(page3, 1)
		assert.Equal(retPlg, plg)
		for _, item := range page2 {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
		}
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page4, retPlg, ttime, err := repo.listSets(
			context.Background(),
			catalog.GetPublicId(),
			WithLimit(2),
			WithStartPageAfterItem(page3[0]),
		)
		require.NoError(err)
		require.Empty(page4)
		require.Empty(retPlg)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
}

func Test_listDeletedSetIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	plg := plugin.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &loopback.WrappingPluginHostClient{Server: &loopback.TestPluginServer{}},
	}
	catalog := TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms, sched, plgm)
	require.NoError(t, err)

	// Expect no entries at the start
	deletedIds, ttime, err := repo.listDeletedSetIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a set
	s := TestSet(t, conn, testKms, sched, catalog, plgm)
	_, err = repo.DeleteSet(ctx, proj.GetPublicId(), s.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime, err = repo.listDeletedSetIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{s.GetPublicId()}, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listDeletedSetIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_estimatedHostSetCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	plg := plugin.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &loopback.WrappingPluginHostClient{Server: &loopback.TestPluginServer{}},
	}
	catalog := TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId())

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms, sched, plgm)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedSetCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create a set, expect 1 entries
	s := TestSet(t, conn, testKms, sched, catalog, plgm)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedSetCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete the set, expect 0 again
	_, err = repo.DeleteSet(ctx, proj.GetPublicId(), s.GetPublicId())
	require.NoError(t, err)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedSetCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func TestRepository_DeleteSet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := plugin.TestPlugin(t, conn, "create")

	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(loopback.TestPluginHostServer{OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
			return &plgpb.OnCreateSetResponse{}, nil
		}}),
	}
	c := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	hostSet := TestSet(t, conn, kms, sched, c, plgm)
	hostSet2 := TestSet(t, conn, kms, sched, c, plgm)

	newHostSetId, err := newHostSetId(ctx)
	require.NoError(t, err)
	tests := []struct {
		name          string
		in            string
		pluginChecker func(*plgpb.OnDeleteSetRequest) error
		want          int
		wantIsErr     errors.Code
	}{
		{
			name: "With no public id",
			pluginChecker: func(req *plgpb.OnDeleteSetRequest) error {
				assert.Fail(t, "The plugin shouldn't be called")
				return nil
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "With non existing host set id",
			in:   newHostSetId,
			pluginChecker: func(req *plgpb.OnDeleteSetRequest) error {
				assert.Fail(t, "The plugin shouldn't be called")
				return nil
			},
			want: 0,
		},
		{
			name: "With existing host set id",
			in:   hostSet.PublicId,
			pluginChecker: func(req *plgpb.OnDeleteSetRequest) error {
				assert.Equal(t, c.GetPublicId(), req.GetCatalog().GetId())
				assert.Equal(t, hostSet.GetPublicId(), req.GetSet().GetId())
				return nil
			},
			want: 1,
		},
		{
			name: "Ignores plugin errors",
			in:   hostSet2.PublicId,
			pluginChecker: func(req *plgpb.OnDeleteSetRequest) error {
				assert.Equal(t, c.GetPublicId(), req.GetCatalog().GetId())
				assert.Equal(t, hostSet2.GetPublicId(), req.GetSet().GetId())
				return fmt.Errorf("test error")
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteSet(ctx, prj.PublicId, tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Zero(got)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func printoutTable(t *testing.T, rw *db.Db) {
	ctx := context.Background()
	hsas := []*hostSetAgg{}
	require.NoError(t, rw.SearchWhere(ctx, &hsas, "", nil))
	for _, hs := range hsas {
		t.Logf("%#v", hs)
	}
}
