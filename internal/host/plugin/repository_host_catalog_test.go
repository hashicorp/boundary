package plugin

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
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
	plg := hostplg.TestPlugin(t, conn, "test")
	unimplementedPlugin := hostplg.TestPlugin(t, conn, "unimplemented")

	// gotPluginAttrs tracks which attributes a plugin has received through a closure and can be compared in the
	// test against the expected values sent to the plugin.
	var gotPluginAttrs *structpb.Struct
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &WrappingPluginClient{
			Server: &TestPluginServer{
				OnCreateCatalogFn: func(_ context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
					gotPluginAttrs = req.GetCatalog().GetAttributes()
					return &plgpb.OnCreateCatalogResponse{Persisted: &plgpb.HostCatalogPersisted{Secrets: req.GetCatalog().GetSecrets()}}, nil
				},
			},
		},
		unimplementedPlugin.GetPublicId(): &WrappingPluginClient{Server: &plgpb.UnimplementedHostPluginServiceServer{}},
	}

	tests := []struct {
		name       string
		in         *HostCatalog
		opts       []Option
		want       *HostCatalog
		wantSecret *structpb.Struct
		wantIsErr  errors.Code
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
			name: "no-scope",
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
					ScopeId:    prj.GetPublicId(),
					Attributes: []byte{},
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-attributes",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:  prj.GetPublicId(),
					PluginId: plg.GetPublicId(),
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:    prj.GetPublicId(),
					PluginId:   plg.GetPublicId(),
					Attributes: []byte{},
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:    prj.GetPublicId(),
					PluginId:   plg.GetPublicId(),
					Attributes: []byte{},
				},
			},
		},
		{
			name: "valid-unimplemented-plugin",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:    prj.GetPublicId(),
					PluginId:   unimplementedPlugin.GetPublicId(),
					Attributes: []byte{},
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:    prj.GetPublicId(),
					PluginId:   unimplementedPlugin.GetPublicId(),
					Attributes: []byte{},
				},
			},
		},
		{
			name: "not-found-plugin",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:    prj.GetPublicId(),
					PluginId:   "unknown_plugin",
					Attributes: []byte{},
				},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid-with-name",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:       "test-name-repo",
					ScopeId:    prj.GetPublicId(),
					PluginId:   plg.GetPublicId(),
					Attributes: []byte{},
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:       "test-name-repo",
					ScopeId:    prj.GetPublicId(),
					PluginId:   plg.GetPublicId(),
					Attributes: []byte{},
				},
			},
		},
		{
			name: "valid-with-description",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
					ScopeId:     prj.GetPublicId(),
					PluginId:    plg.GetPublicId(),
					Attributes:  []byte{},
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
					ScopeId:     prj.GetPublicId(),
					PluginId:    plg.GetPublicId(),
					Attributes:  []byte{},
				},
			},
		},
		{
			name: "valid-with-attributes",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:  prj.GetPublicId(),
					PluginId: plg.GetPublicId(),
					Attributes: func() []byte {
						st, err := structpb.NewStruct(map[string]interface{}{"k1": "foo"})
						require.NoError(t, err)
						b, err := proto.Marshal(st)
						require.NoError(t, err)
						return b
					}(),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:  prj.GetPublicId(),
					PluginId: plg.GetPublicId(),
					Attributes: func() []byte {
						st, err := structpb.NewStruct(map[string]interface{}{"k1": "foo"})
						require.NoError(t, err)
						b, err := proto.Marshal(st)
						require.NoError(t, err)
						return b
					}(),
				},
			},
		},
		{
			name: "valid-with-secret",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
					ScopeId:     prj.GetPublicId(),
					PluginId:    plg.GetPublicId(),
					Attributes:  []byte{},
				},
				Secrets: func() *structpb.Struct {
					st, err := structpb.NewStruct(map[string]interface{}{
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
					ScopeId:     prj.GetPublicId(),
					PluginId:    plg.GetPublicId(),
					Attributes:  []byte{},
				},
			},
			wantSecret: func() *structpb.Struct {
				st, err := structpb.NewStruct(map[string]interface{}{
					"k1": "v1",
					"k2": 2,
					"k3": nil,
				})
				require.NoError(t, err)
				return st
			}(),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			kmsCache := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kmsCache, sched, plgm)
			assert.NoError(err)
			assert.NotNil(repo)
			got, _, err := repo.CreateCatalog(ctx, tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(t, err)
			assert.Empty(tt.in.PublicId)
			assert.NotNil(got)
			assertPluginBasedPublicId(t, HostCatalogPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)

			// wantedPluginAttributes := &structpb.Struct{}
			// require.NoError(t, proto.Unmarshal(tt.want.GetAttributes(), wantedPluginAttributes))
			gotB, err := proto.Marshal(gotPluginAttrs)
			require.NoError(t, err)
			assert.Equal(tt.want.GetAttributes(), gotB)

			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

			cSecret := allocHostCatalogSecret()
			err = rw.LookupWhere(ctx, &cSecret, "catalog_id=?", got.GetPublicId())
			if tt.wantSecret == nil {
				assert.Nil(got.Secrets)
				require.Error(t, err)
				require.True(t, errors.IsNotFoundError(err))
				return
			}
			require.NoError(t, err)
			require.Empty(t, cSecret.Secret)
			require.NotEmpty(t, cSecret.CtSecret)

			dbWrapper, err := kmsCache.GetWrapper(ctx, got.GetScopeId(), kms.KeyPurposeDatabase)
			require.NoError(t, err)
			require.NoError(t, cSecret.decrypt(ctx, dbWrapper))

			st := &structpb.Struct{}
			require.NoError(t, proto.Unmarshal(cSecret.Secret, st))
			assert.Empty(cmp.Diff(tt.wantSecret, st, protocmp.Transform()))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sched, plgm)
		assert.NoError(err)
		assert.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		in := &HostCatalog{
			HostCatalog: &store.HostCatalog{
				ScopeId:    prj.GetPublicId(),
				Name:       "test-name-repo",
				PluginId:   plg.GetPublicId(),
				Attributes: []byte{},
			},
		}

		got, _, err := repo.CreateCatalog(context.Background(), in)
		assert.NoError(err)
		assert.NotNil(got)
		assertPluginBasedPublicId(t, HostCatalogPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, _, err := repo.CreateCatalog(context.Background(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-scopes", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sched, plgm)
		assert.NoError(err)
		assert.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		in := &HostCatalog{
			HostCatalog: &store.HostCatalog{
				Name:       "test-name-repo",
				PluginId:   plg.GetPublicId(),
				Attributes: []byte{},
			},
		}
		in2 := in.clone()

		in.ScopeId = prj.GetPublicId()
		got, _, err := repo.CreateCatalog(context.Background(), in)
		assert.NoError(err)
		assert.NotNil(got)
		assertPluginBasedPublicId(t, HostCatalogPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.ScopeId = org.GetPublicId()
		got2, _, err := repo.CreateCatalog(context.Background(), in2)
		assert.NoError(err)
		assert.NotNil(got2)
		assertPluginBasedPublicId(t, HostCatalogPrefix, got2.PublicId)
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
	orgScope, projectScope := iam.TestScopes(t, iam.TestRepo(t, dbConn, dbWrapper))

	// Define a plugin "manager", basically just a map with a mock
	// plugin in it.  This also includes functionality to capture the
	// state, and set an error and the returned secrets to nil. Note
	// that the way that this is set up means that the tests cannot run
	// in parallel, but there could be other factors affecting that as
	// well.
	var setRespSecretsNil bool
	var gotOnUpdateCatalogRequest *plgpb.OnUpdateCatalogRequest
	var pluginError error
	testPlugin := hostplg.TestPlugin(t, dbConn, "test")
	testPluginMap := map[string]plgpb.HostPluginServiceClient{
		testPlugin.GetPublicId(): &WrappingPluginClient{
			Server: &TestPluginServer{
				OnUpdateCatalogFn: func(_ context.Context, req *plgpb.OnUpdateCatalogRequest) (*plgpb.OnUpdateCatalogResponse, error) {
					gotOnUpdateCatalogRequest = req
					respSecrets := req.GetNewCatalog().GetSecrets()
					if setRespSecretsNil {
						respSecrets = nil
						setRespSecretsNil = false
					}

					return &plgpb.OnUpdateCatalogResponse{Persisted: &plgpb.HostCatalogPersisted{Secrets: respSecrets}}, pluginError
				},
			},
		},
	}

	// Set up two existing catalogs for duplicate tests, one with org
	// scope, one with project scope.
	const (
		testDuplicateCatalogNameOrgScope     = "duplicate-catalog-name-org-scope"
		testDuplicateCatalogNameProjectScope = "duplicate-catalog-name-project-scope"
	)

	// Org scope
	existingOrgScopeCatalog := TestCatalog(t, dbConn, orgScope.PublicId, testPlugin.GetPublicId())
	existingOrgScopeCatalog.Name = testDuplicateCatalogNameOrgScope
	numCatUpdated, err := dbRW.Update(ctx, existingOrgScopeCatalog, []string{"name"}, []string{})
	require.NoError(t, err)
	require.Equal(t, 1, numCatUpdated)

	// Project scope
	existingProjectScopeCatalog := TestCatalog(t, dbConn, projectScope.PublicId, testPlugin.GetPublicId())
	existingProjectScopeCatalog.Name = testDuplicateCatalogNameProjectScope
	numCatUpdated, err = dbRW.Update(ctx, existingProjectScopeCatalog, []string{"name"}, []string{})
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

	changeScopeId := func(s string) changeHostCatalogFunc {
		return func(c *HostCatalog) *HostCatalog {
			c.ScopeId = s
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

	changeAttributes := func(m map[string]interface{}) changeHostCatalogFunc {
		return func(c *HostCatalog) *HostCatalog {
			c.Attributes = mustMarshal(m)
			return c
		}
	}

	changeSecrets := func(m map[string]interface{}) changeHostCatalogFunc {
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

	checkAttributes := func(want map[string]interface{}) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			require := require.New(t)
			st := &structpb.Struct{}
			require.NoError(proto.Unmarshal(gotCatalog.Attributes, st))
			assert.Empty(cmp.Diff(mustStruct(want), st, protocmp.Transform()))
		}
	}

	checkSecrets := func(want map[string]interface{}) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			require := require.New(t)

			cSecret := allocHostCatalogSecret()
			err := dbRW.LookupWhere(ctx, &cSecret, "catalog_id=?", gotCatalog.GetPublicId())
			require.NoError(err)
			require.Empty(cSecret.Secret)
			require.NotEmpty(cSecret.CtSecret)

			dbWrapper, err := dbKmsCache.GetWrapper(ctx, gotCatalog.GetScopeId(), kms.KeyPurposeDatabase)
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
			err := dbRW.LookupWhere(ctx, &cSecret, "catalog_id=?", gotCatalog.GetPublicId())
			assert.Error(err)
			assert.True(errors.IsNotFoundError(err))
		}
	}

	// checkUpdateCatalogRequestCurrentName := func(want string) checkFunc {
	// 	return func(t *testing.T, ctx context.Context) {
	// 		t.Helper()
	// 		assert := assert.New(t)
	// 		assert.Equal(wrapperspb.String(want), gotOnUpdateCatalogRequest.CurrentCatalog.Name)
	// 	}
	// }

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

	// checkUpdateCatalogRequestCurrentDescription := func(want string) checkFunc {
	// 	return func(t *testing.T, ctx context.Context) {
	// 		t.Helper()
	// 		assert := assert.New(t)
	// 		assert.Equal(wrapperspb.String(want), gotOnUpdateCatalogRequest.CurrentCatalog.Description)
	// 	}
	// }

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

	// checkUpdateCatalogRequestNewDescriptionNil := func() checkFunc {
	// 	return func(t *testing.T, ctx context.Context) {
	// 		t.Helper()
	// 		assert := assert.New(t)
	// 		assert.Nil(gotOnUpdateCatalogRequest.NewCatalog.Description)
	// 	}
	// }

	checkUpdateCatalogRequestCurrentAttributes := func(want map[string]interface{}) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Empty(cmp.Diff(mustStruct(want), gotOnUpdateCatalogRequest.CurrentCatalog.Attributes, protocmp.Transform()))
		}
	}

	checkUpdateCatalogRequestNewAttributes := func(want map[string]interface{}) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Empty(cmp.Diff(mustStruct(want), gotOnUpdateCatalogRequest.NewCatalog.Attributes, protocmp.Transform()))
		}
	}

	checkUpdateCatalogRequestPersistedSecrets := func(want map[string]interface{}) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Empty(cmp.Diff(mustStruct(want), gotOnUpdateCatalogRequest.Persisted.Secrets, protocmp.Transform()))
		}
	}

	checkUpdateCatalogRequestSecrets := func(want map[string]interface{}) checkFunc {
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
			name:        "missing scope id",
			changeFuncs: []changeHostCatalogFunc{changeScopeId("")},
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
			name:        "update name (duplicate, same scope)",
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
				checkUpdateCatalogRequestCurrentNameNil(),
				checkUpdateCatalogRequestNewName("foo"),
				checkName("foo"),
				checkSecrets(map[string]interface{}{
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
				checkUpdateCatalogRequestCurrentNameNil(),
				checkUpdateCatalogRequestNewNameNil(),
				checkName(""),
				checkSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update name (duplicate, different scope)",
			changeFuncs: []changeHostCatalogFunc{changeName(testDuplicateCatalogNameOrgScope)},
			version:     2,
			fieldMask:   []string{"name"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateCatalogRequestCurrentNameNil(),
				checkUpdateCatalogRequestNewName(testDuplicateCatalogNameOrgScope),
				checkName(testDuplicateCatalogNameOrgScope),
				checkSecrets(map[string]interface{}{
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
				checkUpdateCatalogRequestCurrentDescriptionNil(),
				checkUpdateCatalogRequestNewDescription("foo"),
				checkDescription("foo"),
				checkSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (add)",
			changeFuncs: []changeHostCatalogFunc{changeAttributes(map[string]interface{}{
				"baz": "qux",
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateCatalogRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				checkUpdateCatalogRequestNewAttributes(map[string]interface{}{
					"foo": "bar",
					"baz": "qux",
				}),
				checkAttributes(map[string]interface{}{
					"foo": "bar",
					"baz": "qux",
				}),
				checkSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (overwrite)",
			changeFuncs: []changeHostCatalogFunc{changeAttributes(map[string]interface{}{
				"foo": "baz",
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateCatalogRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				checkUpdateCatalogRequestNewAttributes(map[string]interface{}{
					"foo": "baz",
				}),
				checkAttributes(map[string]interface{}{
					"foo": "baz",
				}),
				checkSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (null)",
			changeFuncs: []changeHostCatalogFunc{changeAttributes(map[string]interface{}{
				"foo": nil,
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateCatalogRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				checkUpdateCatalogRequestNewAttributes(map[string]interface{}{}),
				checkAttributes(map[string]interface{}{}),
				checkSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (combined)",
			changeFuncs: []changeHostCatalogFunc{changeAttributes(map[string]interface{}{
				"a":   "b",
				"foo": "baz",
			})},
			version:   2,
			fieldMask: []string{"attributes.a", "attributes.foo"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateCatalogRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				checkUpdateCatalogRequestNewAttributes(map[string]interface{}{
					"a":   "b",
					"foo": "baz",
				}),
				checkAttributes(map[string]interface{}{
					"a":   "b",
					"foo": "baz",
				}),
				checkSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update secrets",
			changeFuncs: []changeHostCatalogFunc{changeSecrets(map[string]interface{}{
				"three": "four",
			})},
			version:   2,
			fieldMask: []string{"secrets.three"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateCatalogRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkUpdateCatalogRequestSecrets(map[string]interface{}{
					"three": "four",
				}),
				checkSecrets(map[string]interface{}{
					"three": "four",
				}),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:               "update secrets, return nil secrets from plugin",
			withRespSecretsNil: true,
			changeFuncs: []changeHostCatalogFunc{changeSecrets(map[string]interface{}{
				"three": "four",
			})},
			version:   2,
			fieldMask: []string{"secrets.three"},
			wantCheckFuncs: []checkFunc{
				checkVersion(2), // no-op
				checkUpdateCatalogRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkUpdateCatalogRequestSecrets(map[string]interface{}{
					"three": "four",
				}),
				checkSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(db.NoRowsAffected),
			},
		},
		{
			name:        "delete secrets",
			changeFuncs: []changeHostCatalogFunc{changeSecrets(map[string]interface{}{})},
			version:     2,
			fieldMask:   []string{"secrets"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateCatalogRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkUpdateCatalogRequestSecrets(map[string]interface{}{}),
				checkSecretsDeleted(),
				checkNumUpdated(1),
				checkVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update name and secrets",
			changeFuncs: []changeHostCatalogFunc{
				changeName("foo"),
				changeSecrets(map[string]interface{}{
					"three": "four",
				}),
			},
			version:   2,
			fieldMask: []string{"name", "secrets.three"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateCatalogRequestCurrentNameNil(),
				checkUpdateCatalogRequestNewName("foo"),
				checkUpdateCatalogRequestSecrets(map[string]interface{}{
					"three": "four",
				}),
				checkName("foo"),
				checkSecrets(map[string]interface{}{
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
	setupHostCatalog := func(t *testing.T, ctx context.Context) (*HostCatalog, func()) {
		t.Helper()
		require := require.New(t)

		cat := TestCatalog(t, dbConn, projectScope.PublicId, testPlugin.GetPublicId())
		// Set some (default) attributes on our test catalog
		cat.Attributes = mustMarshal(map[string]interface{}{
			"foo": "bar",
		})

		numCatUpdated, err := dbRW.Update(ctx, cat, []string{"attributes"}, []string{})
		require.NoError(err)
		require.Equal(1, numCatUpdated)

		// Set up some secrets
		cSecretProto := mustStruct(map[string]interface{}{
			"one": "two",
		})
		cSecret, err := newHostCatalogSecret(ctx, cat.GetPublicId(), cSecretProto)
		require.NoError(err)
		scopeWrapper, err := dbKmsCache.GetWrapper(ctx, cat.GetScopeId(), kms.KeyPurposeDatabase)
		require.NoError(err)
		require.NoError(cSecret.encrypt(ctx, scopeWrapper))
		cSecretQ, cSecretV := cSecret.upsertQuery()
		secretsUpdated, err := dbRW.Exec(ctx, cSecretQ, cSecretV)
		require.NoError(err)
		require.Equal(1, secretsUpdated)

		cleanupFunc := func() {
			t.Helper()
			assert := assert.New(t)
			n, err := dbRW.Delete(ctx, cat)
			assert.NoError(err)
			assert.Equal(1, n)
		}

		return cat, cleanupFunc
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			origCat, cleanup := setupHostCatalog(t, ctx)
			defer cleanup()

			pluginMap := testPluginMap
			if tt.withEmptyPluginMap {
				pluginMap = make(map[string]plgpb.HostPluginServiceClient)
			}
			pluginError = tt.withPluginError
			defer func() { pluginError = nil }()
			repo, err := NewRepository(dbRW, dbRW, dbKmsCache, sched, pluginMap)
			require.NoError(err)
			require.NotNil(repo)

			workingCat := origCat.clone()
			for _, cf := range tt.changeFuncs {
				workingCat = cf(workingCat)
			}

			setRespSecretsNil = tt.withRespSecretsNil
			gotCatalog, gotNumUpdated, err = repo.UpdateCatalog(ctx, workingCat, tt.version, tt.fieldMask)
			if tt.wantIsErr != 0 {
				require.Equal(db.NoRowsAffected, gotNumUpdated)
				require.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			defer func() { gotOnUpdateCatalogRequest = nil }()

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
	plg := hostplg.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &WrappingPluginClient{Server: &TestPluginServer{}},
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
			repo, err := NewRepository(rw, rw, kms, sched, plgm)
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

func TestRepository_ListCatalogs_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	plg := hostplg.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &WrappingPluginClient{Server: &TestPluginServer{}},
	}
	repo, err := NewRepository(rw, rw, kms, sched, plgm)
	assert.NoError(t, err)
	assert.NotNil(t, repo)

	const numPerScope = 10
	var projs []string
	var total int
	for i := 0; i < numPerScope; i++ {
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		projs = append(projs, prj.GetPublicId())
		for j := 0; j < numPerScope; j++ {
			TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
			total++
		}
	}

	got, plgs, err := repo.ListCatalogs(context.Background(), projs)
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
	assert.Contains(t, plgs, plg)
}

func TestRepository_DeleteCatalog(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := hostplg.TestPlugin(t, conn, "test")
	pluginInstance := &TestPluginServer{}
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &WrappingPluginClient{Server: pluginInstance},
	}
	cat := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	cat2 := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	badId, err := newHostCatalogId(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, badId)

	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms, sched, plgm)
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
	plg := hostplg.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &WrappingPluginClient{Server: &TestPluginServer{}},
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
			repo, err := NewRepository(rw, rw, kms, sched, plgm)
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

func assertPluginBasedPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want 1 '_' in PublicId, got %d in %q", len(parts), actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

// mustStruct creates a structpb.Struct, and panics if there is an
// error.
func mustStruct(in map[string]interface{}) *structpb.Struct {
	out, err := structpb.NewStruct(in)
	if err != nil {
		panic(err)
	}

	return out
}

// mustMarshal behaves like mustStruct but also converts the Struct
// to wire-format data.
func mustMarshal(in map[string]interface{}) []byte {
	b, err := proto.Marshal(mustStruct(in))
	if err != nil {
		panic(err)
	}

	return b
}
