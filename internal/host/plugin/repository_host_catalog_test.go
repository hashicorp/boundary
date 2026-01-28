// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/patchstruct"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	plgstore "github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestRepository_CreateCatalog(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	unimplementedPlugin := plugin.TestPlugin(t, conn, "unimplemented")

	const normalizeToSliceKey = "normalize_to_slice"

	tests := []struct {
		name             string
		in               *HostCatalog
		opts             []Option
		want             *HostCatalog
		wantPluginCalled bool
		wantSecret       *structpb.Struct
		wantIsErr        errors.Code
	}{
		{
			name:      "nil-catalog",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name:      "nil-embedded-catalog",
			in:        &HostCatalog{},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-project",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					PluginId:   plg.GetPublicId(),
					Attributes: []byte{},
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-plugin",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ProjectId:  prj.GetPublicId(),
					Attributes: []byte{},
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-attributes",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ProjectId: prj.GetPublicId(),
					PluginId:  plg.GetPublicId(),
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ProjectId:  prj.GetPublicId(),
					PluginId:   plg.GetPublicId(),
					Attributes: []byte{},
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ProjectId:  prj.GetPublicId(),
					PluginId:   plg.GetPublicId(),
					Attributes: []byte{},
				},
			},
			wantPluginCalled: true,
		},
		{
			name: "valid-unimplemented-plugin",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ProjectId:  prj.GetPublicId(),
					PluginId:   unimplementedPlugin.GetPublicId(),
					Attributes: []byte{},
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ProjectId:  prj.GetPublicId(),
					PluginId:   unimplementedPlugin.GetPublicId(),
					Attributes: []byte{},
				},
			},
			wantPluginCalled: true,
		},
		{
			name: "not-found-plugin",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ProjectId:  prj.GetPublicId(),
					PluginId:   "unknown_plugin",
					Attributes: []byte{},
				},
			},
			wantIsErr: errors.RecordNotFound,
		},
		{
			name: "valid-with-name",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:       "test-name-repo",
					ProjectId:  prj.GetPublicId(),
					PluginId:   plg.GetPublicId(),
					Attributes: []byte{},
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:       "test-name-repo",
					ProjectId:  prj.GetPublicId(),
					PluginId:   plg.GetPublicId(),
					Attributes: []byte{},
				},
			},
			wantPluginCalled: true,
		},
		{
			name: "valid-with-description",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
					ProjectId:   prj.GetPublicId(),
					PluginId:    plg.GetPublicId(),
					Attributes:  []byte{},
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
					ProjectId:   prj.GetPublicId(),
					PluginId:    plg.GetPublicId(),
					Attributes:  []byte{},
				},
			},
			wantPluginCalled: true,
		},
		{
			name: "valid-with-attributes",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ProjectId: prj.GetPublicId(),
					PluginId:  plg.GetPublicId(),
					Attributes: func() []byte {
						st, err := structpb.NewStruct(map[string]any{
							"k1":                nil,
							"nilkey":            nil,
							normalizeToSliceKey: "normalizeme",
						})
						require.NoError(t, err)
						b, err := proto.Marshal(st)
						require.NoError(t, err)
						return b
					}(),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ProjectId: prj.GetPublicId(),
					PluginId:  plg.GetPublicId(),
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
		{
			name: "valid-with-secret",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
					ProjectId:   prj.GetPublicId(),
					PluginId:    plg.GetPublicId(),
					Attributes:  []byte{},
				},
				Secrets: func() *structpb.Struct {
					st, err := structpb.NewStruct(map[string]any{
						"k1": "v1",
						"k2": 2,
						"k3": nil,
					})
					require.NoError(t, err)
					return st
				}(),
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
					ProjectId:   prj.GetPublicId(),
					PluginId:    plg.GetPublicId(),
					Attributes:  []byte{},
				},
			},
			wantSecret: func() *structpb.Struct {
				st, err := structpb.NewStruct(map[string]any{
					"k1": "v1",
					"k2": 2,
					"k3": nil,
				})
				require.NoError(t, err)
				return st
			}(),
			wantPluginCalled: true,
		},
		{
			name: "valid-empty-secrets",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
					ProjectId:   prj.GetPublicId(),
					PluginId:    plg.GetPublicId(),
					Attributes:  []byte{},
				},
				Secrets: func() *structpb.Struct {
					st, err := structpb.NewStruct(map[string]any{})
					require.NoError(t, err)
					return st
				}(),
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
					ProjectId:   prj.GetPublicId(),
					PluginId:    plg.GetPublicId(),
					Attributes:  []byte{},
				},
			},
			wantSecret: func() *structpb.Struct {
				st, err := structpb.NewStruct(map[string]any{})
				require.NoError(t, err)
				return st
			}(),
			wantPluginCalled: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			kmsCache := kms.TestKms(t, conn, wrapper)

			// gotPluginAttrs tracks which attributes a plugin has received through a closure and can be compared in the
			// test against the expected values sent to the plugin.
			var origPluginAttrs, gotPluginAttrs *structpb.Struct
			if tt.in != nil && tt.in.HostCatalog != nil && len(tt.in.Attributes) > 0 {
				origPluginAttrs = new(structpb.Struct)
				require.NoError(proto.Unmarshal(tt.in.Attributes, origPluginAttrs))
			}

			var pluginCalled bool
			plgm := map[string]plgpb.HostPluginServiceClient{
				plg.GetPublicId(): &loopback.WrappingPluginHostClient{
					Server: &loopback.TestPluginHostServer{
						NormalizeCatalogDataFn: func(_ context.Context, req *plgpb.NormalizeCatalogDataRequest) (*plgpb.NormalizeCatalogDataResponse, error) {
							if req.Attributes == nil {
								return new(plgpb.NormalizeCatalogDataResponse), nil
							}
							var attrs struct {
								NormalizeToSlice string `mapstructure:"normalize_to_slice"`
							}
							require.NoError(mapstructure.Decode(req.Attributes.AsMap(), &attrs))
							if attrs.NormalizeToSlice == "" {
								return new(plgpb.NormalizeCatalogDataResponse), nil
							}
							retAttrs := proto.Clone(req.Attributes).(*structpb.Struct)
							retAttrs.Fields[normalizeToSliceKey] = structpb.NewListValue(&structpb.ListValue{
								Values: []*structpb.Value{structpb.NewStringValue(attrs.NormalizeToSlice)},
							})
							require.NotNil(req.GetPlugin())
							return &plgpb.NormalizeCatalogDataResponse{Attributes: retAttrs}, nil
						},
						OnCreateCatalogFn: func(_ context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
							pluginCalled = true
							gotPluginAttrs = req.GetCatalog().GetAttributes()
							require.NotNil(req.GetCatalog().GetPlugin())
							return &plgpb.OnCreateCatalogResponse{Persisted: &plgpb.HostCatalogPersisted{Secrets: req.GetCatalog().GetSecrets()}}, nil
						},
					},
				},
				unimplementedPlugin.GetPublicId(): &loopback.WrappingPluginHostClient{Server: &loopback.TestPluginHostServer{
					OnCreateCatalogFn: func(ctx context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
						pluginCalled = true
						gotPluginAttrs = req.GetCatalog().GetAttributes()
						return plgpb.UnimplementedHostPluginServiceServer{}.OnCreateCatalog(ctx, req)
					},
				}},
			}
			repo, err := NewRepository(ctx, rw, rw, kmsCache, sched, plgm)
			assert.NoError(err)
			assert.NotNil(repo)
			got, _, err := repo.CreateCatalog(ctx, tt.in, tt.opts...)
			assert.Equal(tt.wantPluginCalled, pluginCalled)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			assert.NotNil(got)
			assertPluginBasedPublicId(t, globals.PluginHostCatalogPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.Equal(tt.want.Attributes, got.Attributes)

			if origPluginAttrs != nil {
				if normalizeVal := origPluginAttrs.Fields[normalizeToSliceKey]; normalizeVal != nil {
					gotVal := gotPluginAttrs.Fields[normalizeToSliceKey]
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
			require.NoError(proto.Unmarshal(tt.want.GetAttributes(), wantedPluginAttributes))
			assert.Empty(cmp.Diff(wantedPluginAttributes, gotPluginAttrs, protocmp.Transform()))

			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

			cSecret := allocHostCatalogSecret()
			err = rw.LookupWhere(ctx, &cSecret, "catalog_id=?", []any{got.GetPublicId()})
			if tt.wantSecret == nil || len(tt.wantSecret.Fields) == 0 {
				assert.Empty(got.Secrets.GetFields())
				require.Error(err)
				require.True(errors.IsNotFoundError(err))
				return
			}
			require.NoError(err)
			require.Empty(cSecret.Secret)
			require.NotEmpty(cSecret.CtSecret)

			dbWrapper, err := kmsCache.GetWrapper(ctx, got.GetProjectId(), kms.KeyPurposeDatabase)
			require.NoError(err)
			require.NoError(cSecret.decrypt(ctx, dbWrapper))

			st := &structpb.Struct{}
			require.NoError(proto.Unmarshal(cSecret.Secret, st))
			assert.Empty(cmp.Diff(tt.wantSecret, st, protocmp.Transform()))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		var pluginCalled bool
		plgm := map[string]plgpb.HostPluginServiceClient{
			plg.GetPublicId(): &loopback.WrappingPluginHostClient{
				Server: &loopback.TestPluginHostServer{
					OnCreateCatalogFn: func(_ context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
						pluginCalled = true
						return &plgpb.OnCreateCatalogResponse{Persisted: &plgpb.HostCatalogPersisted{Secrets: req.GetCatalog().GetSecrets()}}, nil
					},
				},
			},
		}
		repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
		assert.NoError(err)
		assert.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		in := &HostCatalog{
			HostCatalog: &store.HostCatalog{
				ProjectId:  prj.GetPublicId(),
				Name:       "test-name-repo",
				PluginId:   plg.GetPublicId(),
				Attributes: []byte{},
			},
		}

		got, _, err := repo.CreateCatalog(context.Background(), in)
		assert.NoError(err)
		assert.NotNil(got)
		assert.True(pluginCalled)
		assertPluginBasedPublicId(t, globals.PluginHostCatalogPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		// Reset pluginCalled so we can see that the plugin wasn't called w/
		// the duplicate name.
		pluginCalled = false
		got2, _, err := repo.CreateCatalog(context.Background(), in)
		assert.False(pluginCalled)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-projects", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		var pluginCalled bool
		plgm := map[string]plgpb.HostPluginServiceClient{
			plg.GetPublicId(): &loopback.WrappingPluginHostClient{
				Server: &loopback.TestPluginHostServer{
					OnCreateCatalogFn: func(_ context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
						pluginCalled = true
						return &plgpb.OnCreateCatalogResponse{Persisted: &plgpb.HostCatalogPersisted{Secrets: req.GetCatalog().GetSecrets()}}, nil
					},
				},
			},
		}
		repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
		assert.NoError(err)
		assert.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		prj2 := iam.TestProject(t, iam.TestRepo(t, conn, wrapper), org.GetPublicId())
		in := &HostCatalog{
			HostCatalog: &store.HostCatalog{
				Name:       "test-name-repo",
				PluginId:   plg.GetPublicId(),
				Attributes: []byte{},
			},
		}
		in2 := in.clone()

		in.ProjectId = prj.GetPublicId()
		got, _, err := repo.CreateCatalog(context.Background(), in)
		assert.NoError(err)
		assert.NotNil(got)
		assert.True(pluginCalled)
		assertPluginBasedPublicId(t, globals.PluginHostCatalogPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.ProjectId = prj2.GetPublicId()
		pluginCalled = false // reset pluginCalled for this next call to Create
		got2, _, err := repo.CreateCatalog(context.Background(), in2)
		assert.NoError(err)
		assert.NotNil(got2)
		assert.True(pluginCalled)
		assertPluginBasedPublicId(t, globals.PluginHostCatalogPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}

func TestRepository_UpdateCatalog(t *testing.T) {
	ctx := context.Background()
	dbConn, _ := db.TestSetup(t, "postgres")
	dbRW := db.New(dbConn)
	dbWrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, dbConn, dbWrapper)
	dbKmsCache := kms.TestKms(t, dbConn, dbWrapper)
	_, projectScope := iam.TestScopes(t, iam.TestRepo(t, dbConn, dbWrapper))
	_, projectScopeAlt := iam.TestScopes(t, iam.TestRepo(t, dbConn, dbWrapper))

	// Set up two existing catalogs for duplicate tests, one in the
	// same scope that we are working in mostly, and another in a
	// different one. Both are project scopes.
	const (
		testDuplicateCatalogNameProjectScope = "duplicate-catalog-name-project-scope"
		testDuplicateCatalogNameAltScope     = "duplicate-catalog-name-alt-scope"
		normalizeToSliceKey                  = "normalize_to_slice"
	)

	// Define a plugin "manager", basically just a map with a mock
	// plugin in it.  This also includes functionality to capture the
	// state, and set an error and the returned secrets to nil. Note
	// that the way that this is set up means that the tests cannot run
	// in parallel, but there could be other factors affecting that as
	// well.
	var setRespSecretsNil bool
	var gotOnUpdateCatalogRequest *plgpb.OnUpdateCatalogRequest
	var pluginError error
	testPlugin := plugin.TestPlugin(t, dbConn, "test")
	testPluginMap := map[string]plgpb.HostPluginServiceClient{
		testPlugin.GetPublicId(): &loopback.WrappingPluginHostClient{
			Server: &loopback.TestPluginHostServer{
				NormalizeCatalogDataFn: func(_ context.Context, req *plgpb.NormalizeCatalogDataRequest) (*plgpb.NormalizeCatalogDataResponse, error) {
					if req.Attributes == nil {
						return new(plgpb.NormalizeCatalogDataResponse), nil
					}
					var attrs struct {
						NormalizeToSlice string `mapstructure:"normalize_to_slice"`
					}
					require.NoError(t, mapstructure.Decode(req.Attributes.AsMap(), &attrs))
					if attrs.NormalizeToSlice == "" {
						return new(plgpb.NormalizeCatalogDataResponse), nil
					}
					retAttrs := proto.Clone(req.Attributes).(*structpb.Struct)
					retAttrs.Fields[normalizeToSliceKey] = structpb.NewListValue(&structpb.ListValue{
						Values: []*structpb.Value{structpb.NewStringValue(attrs.NormalizeToSlice)},
					})
					require.NotNil(t, req.GetPlugin())
					return &plgpb.NormalizeCatalogDataResponse{Attributes: retAttrs}, nil
				},
				OnUpdateCatalogFn: func(_ context.Context, req *plgpb.OnUpdateCatalogRequest) (*plgpb.OnUpdateCatalogResponse, error) {
					gotOnUpdateCatalogRequest = req
					respSecrets := req.GetNewCatalog().GetSecrets()
					if setRespSecretsNil {
						respSecrets = nil
						setRespSecretsNil = false
					}
					require.NotNil(t, req.GetCurrentCatalog().GetPlugin())
					require.NotNil(t, req.GetNewCatalog().GetPlugin())
					return &plgpb.OnUpdateCatalogResponse{Persisted: &plgpb.HostCatalogPersisted{Secrets: respSecrets}}, pluginError
				},
			},
		},
	}

	// Project scope
	existingProjectScopeCatalog := TestCatalog(t, dbConn, projectScope.PublicId, testPlugin.GetPublicId())
	existingProjectScopeCatalog.Name = testDuplicateCatalogNameProjectScope
	numCatUpdated, err := dbRW.Update(ctx, existingProjectScopeCatalog, []string{"name"}, []string{})
	require.NoError(t, err)
	require.Equal(t, 1, numCatUpdated)

	// Alternate scope
	existingAltScopeCatalog := TestCatalog(t, dbConn, projectScopeAlt.PublicId, testPlugin.GetPublicId())
	existingAltScopeCatalog.Name = testDuplicateCatalogNameAltScope
	numCatUpdated, err = dbRW.Update(ctx, existingAltScopeCatalog, []string{"name"}, []string{})
	require.NoError(t, err)
	require.Equal(t, 1, numCatUpdated)

	// Define some helpers here to make the test table more readable.
	type changeHostCatalogFunc func(c *HostCatalog) *HostCatalog

	changePublicId := func(s string) changeHostCatalogFunc {
		return func(c *HostCatalog) *HostCatalog {
			c.PublicId = s
			return c
		}
	}

	changeProjectId := func(s string) changeHostCatalogFunc {
		return func(c *HostCatalog) *HostCatalog {
			c.ProjectId = s
			return c
		}
	}

	changeName := func(s string) changeHostCatalogFunc {
		return func(c *HostCatalog) *HostCatalog {
			c.Name = s
			return c
		}
	}

	changeDescription := func(s string) changeHostCatalogFunc {
		return func(c *HostCatalog) *HostCatalog {
			c.Description = s
			return c
		}
	}

	changeAttributes := func(m map[string]any) changeHostCatalogFunc {
		return func(c *HostCatalog) *HostCatalog {
			c.Attributes = mustMarshal(m)
			return c
		}
	}

	changeSecrets := func(m map[string]any) changeHostCatalogFunc {
		return func(c *HostCatalog) *HostCatalog {
			c.Secrets = mustStruct(m)
			return c
		}
	}

	changeCatalogToNil := func() changeHostCatalogFunc {
		return func(_ *HostCatalog) *HostCatalog {
			return nil
		}
	}

	changeEmbeddedCatalogToNil := func() changeHostCatalogFunc {
		return func(c *HostCatalog) *HostCatalog {
			c.HostCatalog = nil
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
	type checkFunc func(t *testing.T, ctx context.Context)
	var (
		gotCatalog    *HostCatalog
		gotNumUpdated int
	)

	checkName := func(want string) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(want, gotCatalog.Name)
		}
	}

	checkDescription := func(want string) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(want, gotCatalog.Description)
		}
	}

	checkVersion := func(want uint32) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(want, gotCatalog.Version)
		}
	}

	checkSecretsHmac := func(notNil bool) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			if notNil {
				assert.NotEmpty(gotCatalog.SecretsHmac)
			} else {
				assert.Empty(gotCatalog.SecretsHmac)
			}
		}
	}

	checkAttributes := func(want map[string]any) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			require := require.New(t)
			st := &structpb.Struct{}
			require.NoError(proto.Unmarshal(gotCatalog.Attributes, st))
			assert.Equal(want, st.AsMap())
			assert.Empty(cmp.Diff(mustStruct(want), st, protocmp.Transform()))
		}
	}

	checkSecrets := func(want map[string]any) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			require := require.New(t)

			cSecret := allocHostCatalogSecret()
			err := dbRW.LookupWhere(ctx, &cSecret, "catalog_id=?", []any{gotCatalog.GetPublicId()})
			require.NoError(err)
			require.Empty(cSecret.Secret)
			require.NotEmpty(cSecret.CtSecret)

			dbWrapper, err := dbKmsCache.GetWrapper(ctx, gotCatalog.GetProjectId(), kms.KeyPurposeDatabase)
			require.NoError(err)
			require.NoError(cSecret.decrypt(ctx, dbWrapper))

			st := &structpb.Struct{}
			require.NoError(proto.Unmarshal(cSecret.Secret, st))
			assert.Empty(cmp.Diff(mustStruct(want), st, protocmp.Transform()))
		}
	}

	checkSecretsDeleted := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)

			cSecret := allocHostCatalogSecret()
			err := dbRW.LookupWhere(ctx, &cSecret, "catalog_id=?", []any{gotCatalog.GetPublicId()})
			assert.Error(err)
			assert.True(errors.IsNotFoundError(err))
		}
	}

	checkUpdateCatalogRequestCurrentNameNil := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Nil(gotOnUpdateCatalogRequest.CurrentCatalog.Name)
		}
	}

	checkUpdateCatalogRequestNewName := func(want string) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(wrapperspb.String(want), gotOnUpdateCatalogRequest.NewCatalog.Name)
		}
	}

	checkUpdateCatalogRequestNewNameNil := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Nil(gotOnUpdateCatalogRequest.NewCatalog.Name)
		}
	}

	checkUpdateCatalogRequestCurrentDescriptionNil := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Nil(gotOnUpdateCatalogRequest.CurrentCatalog.Description)
		}
	}

	checkUpdateCatalogRequestNewDescription := func(want string) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(wrapperspb.String(want), gotOnUpdateCatalogRequest.NewCatalog.Description)
		}
	}

	checkUpdateCatalogRequestNewDescriptionNil := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Nil(gotOnUpdateCatalogRequest.NewCatalog.Description)
		}
	}

	checkUpdateCatalogRequestCurrentAttributes := func(want map[string]any) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Empty(cmp.Diff(mustStruct(want), gotOnUpdateCatalogRequest.CurrentCatalog.GetAttributes(), protocmp.Transform()))
		}
	}

	checkUpdateCatalogRequestNewAttributes := func(want map[string]any) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Empty(cmp.Diff(mustStruct(want), gotOnUpdateCatalogRequest.NewCatalog.GetAttributes(), protocmp.Transform()))
		}
	}

	checkUpdateCatalogRequestPersistedSecrets := func(want map[string]any) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Empty(cmp.Diff(mustStruct(want), gotOnUpdateCatalogRequest.Persisted.Secrets, protocmp.Transform()))
		}
	}

	checkUpdateCatalogRequestSecrets := func(want map[string]any) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Empty(cmp.Diff(mustStruct(want), gotOnUpdateCatalogRequest.NewCatalog.Secrets, protocmp.Transform()))
			// Ensure that the current catalog's secrets value is always zero
			assert.Zero(gotOnUpdateCatalogRequest.CurrentCatalog.Secrets)
		}
	}

	checkNumUpdated := func(want int) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(want, gotNumUpdated)
		}
	}

	checkVerifyCatalogOplog := func(op oplog.OpType) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.NoError(
				db.TestVerifyOplog(
					t,
					dbRW,
					gotCatalog.PublicId,
					db.WithOperation(op),
					db.WithCreateNotBefore(10*time.Second),
				),
			)
		}
	}

	tests := []struct {
		name               string
		withEmptyPluginMap bool
		withRespSecretsNil bool
		withPluginError    error
		changeFuncs        []changeHostCatalogFunc
		version            uint32
		fieldMask          []string
		wantCheckFuncs     []checkFunc
		wantIsErr          errors.Code
	}{
		{
			name:        "nil catalog",
			changeFuncs: []changeHostCatalogFunc{changeCatalogToNil()},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "nil embedded catalog",
			changeFuncs: []changeHostCatalogFunc{changeEmbeddedCatalogToNil()},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "missing public id",
			changeFuncs: []changeHostCatalogFunc{changePublicId("")},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "missing project id",
			changeFuncs: []changeHostCatalogFunc{changeProjectId("")},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:      "empty field mask",
			fieldMask: nil, // Should be testing on len
			wantIsErr: errors.EmptyFieldMask,
		},
		{
			name:        "bad catalog id",
			changeFuncs: []changeHostCatalogFunc{changePublicId("badid")},
			fieldMask:   []string{"name"},
			wantIsErr:   errors.RecordNotFound,
		},
		{
			name:        "version mismatch",
			changeFuncs: []changeHostCatalogFunc{changeName("foo")},
			version:     1,
			fieldMask:   []string{"name"},
			wantIsErr:   errors.VersionMismatch,
		},
		{
			name:               "plugin lookup error",
			withEmptyPluginMap: true,
			version:            2,
			fieldMask:          []string{"name"},
			wantIsErr:          errors.Internal,
		},
		{
			name:            "plugin invocation error",
			withPluginError: errors.New(context.Background(), errors.Internal, "TestRepository_UpdateCatalog/plugin_invocation_error", "test plugin error"),
			version:         2,
			fieldMask:       []string{"name"},
			wantIsErr:       errors.Internal,
		},
		{
			name:        "update name (duplicate, same project)",
			changeFuncs: []changeHostCatalogFunc{changeName(testDuplicateCatalogNameProjectScope)},
			version:     2,
			fieldMask:   []string{"name"},
			wantIsErr:   errors.NotUnique,
		},
		{
			name:        "update name",
			changeFuncs: []changeHostCatalogFunc{changeName("foo")},
			version:     2,
			fieldMask:   []string{"name"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(true),
				checkUpdateCatalogRequestCurrentNameNil(),
				checkUpdateCatalogRequestNewName("foo"),
				checkName("foo"),
				checkSecrets(map[string]any{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update name to same",
			changeFuncs: []changeHostCatalogFunc{changeName("")},
			version:     2,
			fieldMask:   []string{"name"},
			wantCheckFuncs: []checkFunc{
				checkVersion(2), // Version remains same even though row is updated
				checkSecretsHmac(true),
				checkUpdateCatalogRequestCurrentNameNil(),
				checkUpdateCatalogRequestNewNameNil(),
				checkName(""),
				checkSecrets(map[string]any{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update name (duplicate, different project)",
			changeFuncs: []changeHostCatalogFunc{changeName(testDuplicateCatalogNameAltScope)},
			version:     2,
			fieldMask:   []string{"name"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(true),
				checkUpdateCatalogRequestCurrentNameNil(),
				checkUpdateCatalogRequestNewName(testDuplicateCatalogNameAltScope),
				checkName(testDuplicateCatalogNameAltScope),
				checkSecrets(map[string]any{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update description",
			changeFuncs: []changeHostCatalogFunc{changeDescription("foo")},
			version:     2,
			fieldMask:   []string{"description"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(true),
				checkUpdateCatalogRequestCurrentDescriptionNil(),
				checkUpdateCatalogRequestNewDescription("foo"),
				checkDescription("foo"),
				checkSecrets(map[string]any{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update description to same",
			changeFuncs: []changeHostCatalogFunc{changeDescription("")},
			version:     2,
			fieldMask:   []string{"description"},
			wantCheckFuncs: []checkFunc{
				checkVersion(2), // Version remains same even though row is updated
				checkSecretsHmac(true),
				checkUpdateCatalogRequestCurrentDescriptionNil(),
				checkUpdateCatalogRequestNewDescriptionNil(),
				checkDescription(""),
				checkSecrets(map[string]any{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (add)",
			changeFuncs: []changeHostCatalogFunc{changeAttributes(map[string]any{
				"baz": "qux",
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(true),
				checkUpdateCatalogRequestCurrentAttributes(map[string]any{
					"foo": "bar",
				}),
				checkUpdateCatalogRequestNewAttributes(map[string]any{
					"foo": "bar",
					"baz": "qux",
				}),
				checkAttributes(map[string]any{
					"foo": "bar",
					"baz": "qux",
				}),
				checkSecrets(map[string]any{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (overwrite)",
			changeFuncs: []changeHostCatalogFunc{changeAttributes(map[string]any{
				"foo":               "baz",
				normalizeToSliceKey: "normalizeme",
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(true),
				checkUpdateCatalogRequestCurrentAttributes(map[string]any{
					"foo": "bar",
				}),
				checkUpdateCatalogRequestNewAttributes(map[string]any{
					"foo":               "baz",
					normalizeToSliceKey: []any{"normalizeme"},
				}),
				checkAttributes(map[string]any{
					"foo":               "baz",
					normalizeToSliceKey: []any{"normalizeme"},
				}),
				checkSecrets(map[string]any{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (null)",
			changeFuncs: []changeHostCatalogFunc{changeAttributes(map[string]any{
				"foo": nil,
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(true),
				checkUpdateCatalogRequestCurrentAttributes(map[string]any{
					"foo": "bar",
				}),
				checkUpdateCatalogRequestNewAttributes(map[string]any{}),
				checkAttributes(map[string]any{}),
				checkSecrets(map[string]any{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (combined)",
			changeFuncs: []changeHostCatalogFunc{changeAttributes(map[string]any{
				"a":   "b",
				"foo": "baz",
			})},
			version:   2,
			fieldMask: []string{"attributes.a", "attributes.foo"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(true),
				checkUpdateCatalogRequestCurrentAttributes(map[string]any{
					"foo": "bar",
				}),
				checkUpdateCatalogRequestNewAttributes(map[string]any{
					"a":   "b",
					"foo": "baz",
				}),
				checkAttributes(map[string]any{
					"a":   "b",
					"foo": "baz",
				}),
				checkSecrets(map[string]any{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update secrets",
			changeFuncs: []changeHostCatalogFunc{changeSecrets(map[string]any{
				"three": "four",
				"five":  "six",
			})},
			version:   2,
			fieldMask: []string{"secrets.three", "secrets.five"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(true),
				checkUpdateCatalogRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
				checkUpdateCatalogRequestSecrets(map[string]any{
					"three": "four",
					"five":  "six",
				}),
				checkSecrets(map[string]any{
					"three": "four",
					"five":  "six",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:               "update secrets, return nil secrets from plugin",
			withRespSecretsNil: true,
			changeFuncs: []changeHostCatalogFunc{changeSecrets(map[string]any{
				"three": "four",
			})},
			version:   2,
			fieldMask: []string{"secrets.three"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3), // incremented due to secrets_hmac
				checkSecretsHmac(true),
				checkUpdateCatalogRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
				checkUpdateCatalogRequestSecrets(map[string]any{
					"three": "four",
				}),
				checkSecrets(map[string]any{
					"one": "two",
				}),
				checkNumUpdated(1),
			},
		},
		{
			name:        "update secrets, return empty secrets from plugin",
			changeFuncs: []changeHostCatalogFunc{changeSecrets(map[string]any{})},
			version:     2,
			fieldMask:   []string{"secrets"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(false),
				checkUpdateCatalogRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
				checkUpdateCatalogRequestSecrets(map[string]any{}),
				checkSecretsDeleted(),
				checkNumUpdated(1),
			},
		},
		{
			name:        "delete secrets",
			changeFuncs: []changeHostCatalogFunc{changeSecrets(map[string]any{})},
			version:     2,
			fieldMask:   []string{"secrets"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(false),
				checkUpdateCatalogRequestPersistedSecrets(map[string]any{
					"one": "two",
				}),
				checkUpdateCatalogRequestSecrets(map[string]any{}),
				checkSecretsDeleted(),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update name and secrets",
			changeFuncs: []changeHostCatalogFunc{
				changeName("foo"),
				changeSecrets(map[string]any{
					"three": "four",
				}),
			},
			version:   2,
			fieldMask: []string{"name", "secrets.three"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkSecretsHmac(true),
				checkUpdateCatalogRequestCurrentNameNil(),
				checkUpdateCatalogRequestNewName("foo"),
				checkUpdateCatalogRequestSecrets(map[string]any{
					"three": "four",
				}),
				checkName("foo"),
				checkSecrets(map[string]any{
					"three": "four",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
	}

	// Finally define a function for bringing the test subject catalog.
	// This function also returns a function to clean up the catalog
	// afterwards.
	setupHostCatalog := func(t *testing.T, ctx context.Context) *HostCatalog {
		t.Helper()
		require := require.New(t)

		cat := TestCatalog(t, dbConn, projectScope.PublicId, testPlugin.GetPublicId())

		// Set up some secrets
		scopeWrapper, err := dbKmsCache.GetWrapper(ctx, cat.GetProjectId(), kms.KeyPurposeDatabase)
		require.NoError(err)
		cat.Secrets = mustStruct(map[string]any{
			"one": "two",
		})
		require.NoError(cat.hmacSecrets(ctx, scopeWrapper))
		cSecret, err := newHostCatalogSecret(ctx, cat.GetPublicId(), cat.Secrets)
		require.NoError(err)
		require.NoError(cSecret.encrypt(ctx, scopeWrapper))
		err = dbRW.Create(ctx, cSecret)
		require.NoError(err)

		// Set some (default) attributes on our test catalog and update SecretsHmac at the same time
		cat.Attributes = mustMarshal(map[string]any{
			"foo": "bar",
		})
		numCatUpdated, err := dbRW.Update(ctx, cat, []string{"attributes", "SecretsHmac"}, []string{})
		require.NoError(err)
		require.Equal(1, numCatUpdated)

		t.Cleanup(func() {
			t.Helper()
			assert := assert.New(t)
			n, err := dbRW.Delete(ctx, cat)
			assert.NoError(err)
			assert.Equal(1, n)
		})

		return cat
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)
			origCat := setupHostCatalog(t, ctx)

			pluginMap := testPluginMap
			if tt.withEmptyPluginMap {
				pluginMap = make(map[string]plgpb.HostPluginServiceClient)
			}
			pluginError = tt.withPluginError
			t.Cleanup(func() { pluginError = nil })
			repo, err := NewRepository(ctx, dbRW, dbRW, dbKmsCache, sched, pluginMap)
			require.NoError(err)
			require.NotNil(repo)

			workingCat := origCat.clone()
			for _, cf := range tt.changeFuncs {
				workingCat = cf(workingCat)
			}

			setRespSecretsNil = tt.withRespSecretsNil
			var gotPlugin *plugin.Plugin
			gotCatalog, gotPlugin, gotNumUpdated, err = repo.UpdateCatalog(ctx, workingCat, tt.version, tt.fieldMask)
			if tt.wantIsErr != 0 {
				require.Equal(db.NoRowsAffected, gotNumUpdated)
				require.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			t.Cleanup(func() { gotOnUpdateCatalogRequest = nil })

			// Quick assertion that the catalog is not nil and that the plugin ID in
			// the catalog and the plugin ID in the returned plugin match. Use assert
			// as that's what our checks use in the table test's defined checks.
			assert.NotNil(gotCatalog)
			assert.NotNil(gotPlugin)
			assert.Equal(gotCatalog.PluginId, gotPlugin.PublicId)
			// Perform checks
			for _, check := range tt.wantCheckFuncs {
				check(t, ctx)
			}
		})
	}
}

func TestRepository_LookupCatalog(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &loopback.WrappingPluginHostClient{Server: &loopback.TestPluginServer{}},
	}
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId(), WithWorkerFilter(`"test" in "/tags/type"`))
	badId, err := newHostCatalogId(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, badId)

	tests := []struct {
		name    string
		id      string
		want    *HostCatalog
		wantErr errors.Code
	}{
		{
			name: "found",
			id:   cat.GetPublicId(),
			want: cat,
		},
		{
			name: "not-found",
			id:   badId,
			want: nil,
		},
		{
			name:    "bad-public-id",
			id:      "",
			want:    nil,
			wantErr: errors.InvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
			assert.NoError(err)
			assert.NotNil(repo)

			got, _, err := repo.LookupCatalog(ctx, tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)

			switch {
			case tt.want == nil:
				assert.Nil(got)
			case tt.want != nil:
				assert.NotNil(got)
				assert.Equal(got, tt.want)
			}
		})
	}
}

func TestRepository_DeleteCatalog(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	pluginInstance := &loopback.TestPluginServer{}
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &loopback.WrappingPluginHostClient{Server: pluginInstance},
	}
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	cat2 := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	badId, err := newHostCatalogId(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, badId)

	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
	assert.NoError(t, err)
	assert.NotNil(t, repo)

	tests := []struct {
		name          string
		id            string
		pluginChecker func(*testing.T, *plgpb.OnDeleteCatalogRequest) error
		want          int
		wantErr       errors.Code
	}{
		{
			name: "found",
			id:   cat.GetPublicId(),
			pluginChecker: func(t *testing.T, req *plgpb.OnDeleteCatalogRequest) error {
				assert.Equal(t, cat.GetPublicId(), req.GetCatalog().GetId())
				return nil
			},
			want: 1,
		},
		{
			name: "ignore error",
			id:   cat2.GetPublicId(),
			pluginChecker: func(t *testing.T, req *plgpb.OnDeleteCatalogRequest) error {
				assert.Equal(t, cat2.GetPublicId(), req.GetCatalog().GetId())
				return fmt.Errorf("This is a test error")
			},
			want: 1,
		},
		{
			name: "not-found",
			id:   badId,
			pluginChecker: func(t *testing.T, req *plgpb.OnDeleteCatalogRequest) error {
				assert.Fail(t, "Should not call the plugin when catalog isn't found")
				return nil
			},
			want: 0,
		},
		{
			name: "bad-public-id",
			id:   "",
			pluginChecker: func(t *testing.T, req *plgpb.OnDeleteCatalogRequest) error {
				assert.Fail(t, "Should not call the plugin for a bad id")
				return nil
			},
			want:    0,
			wantErr: errors.InvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			pluginInstance.OnDeleteCatalogFn = func(_ context.Context, request *plgpb.OnDeleteCatalogRequest) (*plgpb.OnDeleteCatalogResponse, error) {
				require.NotNil(t, request.GetCatalog().GetPlugin())
				return nil, tt.pluginChecker(t, request)
			}
			got, err := repo.DeleteCatalog(context.Background(), tt.id)
			if tt.wantErr != 0 {
				assert.Truef(t, errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got, "row count")
		})
	}
}

func TestRepository_DeleteCatalogX(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := plugin.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &loopback.WrappingPluginHostClient{Server: &loopback.TestPluginServer{}},
	}
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	badId, err := newHostCatalogId(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, badId)

	tests := []struct {
		name    string
		id      string
		want    *HostCatalog
		wantErr errors.Code
	}{
		{
			name: "found",
			id:   cat.GetPublicId(),
			want: cat,
		},
		{
			name: "not-found",
			id:   badId,
			want: nil,
		},
		{
			name:    "bad-public-id",
			id:      "",
			want:    nil,
			wantErr: errors.InvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms, sched, plgm)
			assert.NoError(err)
			assert.NotNil(repo)

			got, _, err := repo.LookupCatalog(ctx, tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)

			switch {
			case tt.want == nil:
				assert.Nil(got)
			case tt.want != nil:
				assert.NotNil(got)
				assert.Equal(got, tt.want)
			}
		})
	}
}

// Create a test scheduled job that we can use to catch when a run is executed.
// We will use this to track whether or not an update was sent in
// TestRepository_UpdateCatalog_SyncSets.
type testSyncJob struct{}

func (j *testSyncJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: 0,
		Total:     1,
	}
}

func (j *testSyncJob) Run(_ context.Context, _ time.Duration) error { return nil }
func (j *testSyncJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return setSyncJobRunInterval, nil
}
func (j *testSyncJob) Name() string        { return setSyncJobName }
func (j *testSyncJob) Description() string { return setSyncJobName }

func TestRepository_UpdateCatalog_SyncSets(t *testing.T) {
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
	// Set up another test catalog that will not have sets on it
	emptyTestCatalog := TestCatalog(t, dbConn, projectScope.PublicId, testPlugin.GetPublicId())

	// Create a couple of host sets.
	set1 := TestSet(t, dbConn, dbKmsCache, sched, testCatalog, dummyPluginMap)
	set1.LastSyncTime = timestamp.New(time.Now())
	set1.NeedSync = false

	numSetsUpdated, err := dbRW.Update(ctx, set1, []string{"LastSyncTime", "NeedSync"}, []string{})
	require.NoError(t, err)
	require.Equal(t, 1, numSetsUpdated)

	// Set 2
	set2 := TestSet(t, dbConn, dbKmsCache, sched, testCatalog, dummyPluginMap)
	set2.LastSyncTime = timestamp.New(time.Now())
	set2.NeedSync = false

	numSetsUpdated, err = dbRW.Update(ctx, set2, []string{"LastSyncTime", "NeedSync"}, []string{})
	require.NoError(t, err)
	require.Equal(t, 1, numSetsUpdated)

	j := &testSyncJob{}
	err = sched.RegisterJob(ctx, j, scheduler.WithNextRunIn(setSyncJobRunInterval))
	require.NoError(t, err)

	repo, err := NewRepository(ctx, dbRW, dbRW, dbKmsCache, sched, dummyPluginMap)
	require.NoError(t, err)
	require.NotNil(t, repo)

	// Load the job repository here so that we can validate run times.
	jobRepo, err := job.NewRepository(ctx, dbRW, dbRW, dbKmsCache)
	require.NoError(t, err)
	require.NotNil(t, repo)

	// Updating an empty catalog should not trigger an update.
	emptyTestCatalog.Attributes = mustMarshal(map[string]any{"foo": "bar"})
	var catalogsUpdated int
	_, _, catalogsUpdated, err = repo.UpdateCatalog(ctx, emptyTestCatalog, emptyTestCatalog.Version, []string{"attributes"})
	require.NoError(t, err)
	require.Equal(t, 1, catalogsUpdated)

	// Job run should have not been requested
	jj, err := jobRepo.LookupJob(ctx, setSyncJobName)
	require.NoError(t, err)
	require.NotNil(t, jj)
	require.GreaterOrEqual(t, time.Until(jj.GetNextScheduledRun().GetTimestamp().AsTime()), time.Second)

	// Updating name should not flag sets for sync
	testCatalog.Name = "foobar"
	testCatalog, _, catalogsUpdated, err = repo.UpdateCatalog(ctx, testCatalog, testCatalog.Version, []string{"name"})
	require.NoError(t, err)
	require.Equal(t, 1, catalogsUpdated)

	gotSet1, _, err := repo.LookupSet(ctx, set1.PublicId)
	require.NoError(t, err)
	require.False(t, gotSet1.NeedSync)
	require.Equal(t, set1.LastSyncTime, gotSet1.LastSyncTime)
	require.Equal(t, set1.Version, gotSet1.Version)

	gotSet2, _, err := repo.LookupSet(ctx, set2.PublicId)
	require.NoError(t, err)
	require.False(t, gotSet2.NeedSync)
	require.Equal(t, set2.LastSyncTime, gotSet2.LastSyncTime)
	require.Equal(t, set2.Version, gotSet2.Version)

	// Job run still should have not been requested
	jj, err = jobRepo.LookupJob(ctx, setSyncJobName)
	require.NoError(t, err)
	require.NotNil(t, jj)
	require.GreaterOrEqual(t, time.Until(jj.GetNextScheduledRun().GetTimestamp().AsTime()), time.Second)

	// Updating attributes should trigger update
	testCatalog.Attributes = mustMarshal(map[string]any{"foo": "bar"})
	_, _, catalogsUpdated, err = repo.UpdateCatalog(ctx, testCatalog, testCatalog.Version, []string{"attributes"})
	require.NoError(t, err)
	require.Equal(t, 1, catalogsUpdated)

	gotSet1, _, err = repo.LookupSet(ctx, set1.PublicId)
	require.NoError(t, err)
	require.True(t, gotSet1.NeedSync)
	require.Equal(t, set1.Version+1, gotSet1.Version)

	gotSet2, _, err = repo.LookupSet(ctx, set2.PublicId)
	require.NoError(t, err)
	require.True(t, gotSet2.NeedSync)
	require.Equal(t, set2.Version+1, gotSet2.Version)

	// Job run should have been requested
	jj, err = jobRepo.LookupJob(ctx, setSyncJobName)
	require.NoError(t, err)
	require.NotNil(t, jj)
	require.Less(t, time.Until(jj.GetNextScheduledRun().GetTimestamp().AsTime()), time.Second)
}

func TestToPluginInfo(t *testing.T) {
	require.Nil(t, toPluginInfo(nil))

	plg := &plugin.Plugin{
		Plugin: &plgstore.Plugin{
			PublicId:    "plg_1234567890",
			Name:        "A Plugin Name",
			Description: "A Plugin Description",
		},
	}
	pi := toPluginInfo(plg)
	require.NotNil(t, pi)
	require.Equal(t, &plugins.PluginInfo{
		Id:          "plg_1234567890",
		Name:        "A Plugin Name",
		Description: "A Plugin Description",
	}, pi)
}

func assertPluginBasedPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want 1 '_' in PublicId, got %d in %q", len(parts), actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

// mustStruct creates a structpb.Struct, and panics if there is an
// error.
func mustStruct(in map[string]any) *structpb.Struct {
	out, err := structpb.NewStruct(in)
	if err != nil {
		panic(err)
	}

	return out
}

// mustMarshal behaves like mustStruct but also converts the Struct
// to wire-format data.
func mustMarshal(in map[string]any) []byte {
	b, err := proto.Marshal(mustStruct(in))
	if err != nil {
		panic(err)
	}

	return b
}
