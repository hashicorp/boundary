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
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestRepository_CreateSet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "create")
	unimplementedPlugin := hostplg.TestPlugin(t, conn, "unimplemented")

	var pluginReceivedAttrs *structpb.Struct
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(TestPluginServer{OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
			pluginReceivedAttrs = req.GetSet().GetAttributes()
			return &plgpb.OnCreateSetResponse{}, nil
		}}),
		unimplementedPlugin.GetPublicId(): NewWrappingPluginClient(&plgpb.UnimplementedHostPluginServiceServer{}),
	}

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	unimplementedPluginCatalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	attrs := []byte{}

	tests := []struct {
		name      string
		in        *HostSet
		opts      []Option
		want      *HostSet
		wantIsErr errors.Code
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
		},
		{
			name: "valid-preferred-endpoints",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:          catalog.PublicId,
					Attributes:         attrs,
					PreferredEndpoints: []string{"cidr:1.2.3.4/32", "dns:a.b.c"},
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:          catalog.PublicId,
					Attributes:         attrs,
					PreferredEndpoints: []string{"cidr:1.2.3.4/32", "dns:a.b.c"},
				},
			},
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
		},
		{
			name: "valid-with-custom-attributes",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:   catalog.PublicId,
					Description: ("test-description-repo"),
					Attributes: func() []byte {
						b, err := proto.Marshal(&structpb.Struct{Fields: map[string]*structpb.Value{"k1": structpb.NewStringValue("foo")}})
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
						b, err := proto.Marshal(&structpb.Struct{Fields: map[string]*structpb.Value{"k1": structpb.NewStringValue("foo")}})
						require.NoError(t, err)
						return b
					}(),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms, sched, plgm)
			require.NoError(err)
			require.NotNil(repo)
			got, plgInfo, err := repo.CreateSet(context.Background(), prj.GetPublicId(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assert.True(strings.HasPrefix(got.GetPublicId(), HostSetPrefix))
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.GetName())
			assert.Equal(tt.want.Description, got.GetDescription())
			assert.Equal(got.GetCreateTime(), got.GetUpdateTime())
			wantedPluginAttributes := &structpb.Struct{}
			require.NoError(proto.Unmarshal(tt.want.Attributes, wantedPluginAttributes))
			assert.Empty(cmp.Diff(wantedPluginAttributes, pluginReceivedAttrs, protocmp.Transform()))
			assert.Empty(cmp.Diff(plgInfo, plg, protocmp.Transform()))

			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms, sched, plgm)
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
		assert.True(strings.HasPrefix(got.GetPublicId(), HostSetPrefix))
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.GetName())
		assert.Equal(in.Description, got.GetDescription())
		assert.Equal(got.GetCreateTime(), got.GetUpdateTime())

		got2, _, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-catalogs", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms, sched, plgm)
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
		got, _, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assert.True(strings.HasPrefix(got.GetPublicId(), HostSetPrefix))
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.GetName())
		assert.Equal(in.Description, got.GetDescription())
		assert.Equal(got.GetCreateTime(), got.GetUpdateTime())

		in2.CatalogId = catalogB.PublicId
		got2, _, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assert.True(strings.HasPrefix(got.GetPublicId(), HostSetPrefix))
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

	// Define a plugin "manager", basically just a map with a mock
	// plugin in it.  This also includes functionality to capture the
	// state, and set an error and the returned secrets to nil. Note
	// that the way that this is set up means that the tests cannot run
	// in parallel, but there could be other factors affecting that as
	// well.
	var gotOnUpdateCallCount int
	var gotOnUpdateSetRequest *plgpb.OnUpdateSetRequest
	var pluginError error
	testPlugin := hostplg.TestPlugin(t, dbConn, "test")
	testPluginMap := map[string]plgpb.HostPluginServiceClient{
		testPlugin.GetPublicId(): &WrappingPluginClient{
			Server: &TestPluginServer{
				OnUpdateSetFn: func(_ context.Context, req *plgpb.OnUpdateSetRequest) (*plgpb.OnUpdateSetResponse, error) {
					gotOnUpdateCallCount++
					gotOnUpdateSetRequest = req
					return &plgpb.OnUpdateSetResponse{}, pluginError
				},
			},
		},
	}

	// Set up a test catalog and the secrets for it
	testCatalog := TestCatalog(t, dbConn, projectScope.PublicId, testPlugin.GetPublicId())
	testCatalogSecret, err := newHostCatalogSecret(ctx, testCatalog.GetPublicId(), mustStruct(map[string]interface{}{
		"one": "two",
	}))
	require.NoError(t, err)
	scopeWrapper, err := dbKmsCache.GetWrapper(ctx, testCatalog.GetScopeId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	require.NoError(t, testCatalogSecret.encrypt(ctx, scopeWrapper))
	testCatalogSecretQ, testCatalogSecretV := testCatalogSecret.upsertQuery()
	secretsUpdated, err := dbRW.Exec(ctx, testCatalogSecretQ, testCatalogSecretV)
	require.NoError(t, err)
	require.Equal(t, 1, secretsUpdated)

	// Create a test duplicate set. We don't use this set, it just
	// exists to ensure that we can test for conflicts when setting
	// the name.
	const testDuplicateSetName = "duplicate-set-name"
	testDuplicateSet := TestSet(t, dbConn, dbKmsCache, sched, testCatalog, testPluginMap)
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

	changePreferredEndpoints := func(s []string) changeHostSetFunc {
		return func(c *HostSet) *HostSet {
			c.PreferredEndpoints = s
			return c
		}
	}

	changeAttributes := func(m map[string]interface{}) changeHostSetFunc {
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
	type checkFunc func(t *testing.T, ctx context.Context)
	var (
		gotSet        *HostSet
		gotNumUpdated int
	)

	checkVersion := func(want uint32) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(want, gotSet.Version)
		}
	}

	checkName := func(want string) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(want, gotSet.Name)
		}
	}

	checkDescription := func(want string) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(want, gotSet.Description)
		}
	}

	checkPreferredEndpoints := func(want []string) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(want, gotSet.PreferredEndpoints)
		}
	}

	checkAttributes := func(want map[string]interface{}) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			require := require.New(t)
			st := &structpb.Struct{}
			require.NoError(proto.Unmarshal(gotSet.Attributes, st))
			assert.Empty(cmp.Diff(mustStruct(want), st, protocmp.Transform()))
		}
	}

	checkUpdateSetRequestCurrentNameNil := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Nil(gotOnUpdateSetRequest.CurrentSet.Name)
		}
	}

	checkUpdateSetRequestNewName := func(want string) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(wrapperspb.String(want), gotOnUpdateSetRequest.NewSet.Name)
		}
	}

	checkUpdateSetRequestNewNameNil := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Nil(gotOnUpdateSetRequest.NewSet.Name)
		}
	}

	checkUpdateSetRequestCurrentDescriptionNil := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Nil(gotOnUpdateSetRequest.CurrentSet.Description)
		}
	}

	checkUpdateSetRequestNewDescription := func(want string) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(wrapperspb.String(want), gotOnUpdateSetRequest.NewSet.Description)
		}
	}

	checkUpdateSetRequestNewDescriptionNil := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Nil(gotOnUpdateSetRequest.NewSet.Description)
		}
	}

	checkUpdateSetRequestCurrentPreferredEndpointsNil := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Nil(gotOnUpdateSetRequest.CurrentSet.PreferredEndpoints)
		}
	}

	checkUpdateSetRequestNewPreferredEndpoints := func(want []string) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(want, gotOnUpdateSetRequest.NewSet.PreferredEndpoints)
		}
	}

	checkUpdateSetRequestNewPreferredEndpointsNil := func() checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Nil(gotOnUpdateSetRequest.NewSet.PreferredEndpoints)
		}
	}

	checkUpdateSetRequestCurrentAttributes := func(want map[string]interface{}) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Empty(cmp.Diff(mustStruct(want), gotOnUpdateSetRequest.CurrentSet.Attributes, protocmp.Transform()))
		}
	}

	checkUpdateSetRequestNewAttributes := func(want map[string]interface{}) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Empty(cmp.Diff(mustStruct(want), gotOnUpdateSetRequest.NewSet.Attributes, protocmp.Transform()))
		}
	}

	checkUpdateSetRequestPersistedSecrets := func(want map[string]interface{}) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Empty(cmp.Diff(mustStruct(want), gotOnUpdateSetRequest.Persisted.Secrets, protocmp.Transform()))
		}
	}

	checkNumUpdated := func(want int) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.Equal(want, gotNumUpdated)
		}
	}

	checkVerifySetOplog := func(op oplog.OpType) checkFunc {
		return func(t *testing.T, ctx context.Context) {
			t.Helper()
			assert := assert.New(t)
			assert.NoError(
				db.TestVerifyOplog(
					t,
					dbRW,
					gotSet.PublicId,
					db.WithOperation(op),
					db.WithCreateNotBefore(10*time.Second),
				),
			)
		}
	}

	tests := []struct {
		name               string
		withScopeId        *string
		withEmptyPluginMap bool
		withPluginError    error
		changeFuncs        []changeHostSetFunc
		version            uint32
		fieldMask          []string
		wantCheckFuncs     []checkFunc
		wantIsErr          errors.Code
	}{
		{
			name:        "nil set",
			changeFuncs: []changeHostSetFunc{changeSetToNil()},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "nil embedded set",
			changeFuncs: []changeHostSetFunc{changeEmbeddedSetToNil()},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "missing public id",
			changeFuncs: []changeHostSetFunc{changePublicId("")},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "missing scope id",
			withScopeId: func() *string { a := ""; return &a }(),
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:      "empty field mask",
			fieldMask: nil, // Should be testing on len
			wantIsErr: errors.EmptyFieldMask,
		},
		{
			name:        "bad set id",
			changeFuncs: []changeHostSetFunc{changePublicId("badid")},
			fieldMask:   []string{"name"},
			wantIsErr:   errors.RecordNotFound,
		},
		{
			name:        "version mismatch",
			changeFuncs: []changeHostSetFunc{changeName("foo")},
			version:     1,
			fieldMask:   []string{"name"},
			wantIsErr:   errors.VersionMismatch,
		},
		{
			name:        "mismatched scope id to catalog scope",
			withScopeId: func() *string { a := "badid"; return &a }(),
			version:     2,
			fieldMask:   []string{"name"},
			wantIsErr:   errors.InvalidParameter,
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
			withPluginError: errors.New(context.Background(), errors.Internal, "TestRepository_UpdateSet/plugin_invocation_error", "test plugin error"),
			version:         2,
			fieldMask:       []string{"name"},
			wantIsErr:       errors.Internal,
		},
		{
			name:        "update name (duplicate)",
			changeFuncs: []changeHostSetFunc{changeName(testDuplicateSetName)},
			version:     2,
			fieldMask:   []string{"name"},
			wantIsErr:   errors.NotUnique,
		},
		{
			name:        "update name",
			changeFuncs: []changeHostSetFunc{changeName("foo")},
			version:     2,
			fieldMask:   []string{"name"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateSetRequestCurrentNameNil(),
				checkUpdateSetRequestNewName("foo"),
				checkName("foo"),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update name to same",
			changeFuncs: []changeHostSetFunc{changeName("")},
			version:     2,
			fieldMask:   []string{"name"},
			wantCheckFuncs: []checkFunc{
				checkVersion(2), // Version remains same even though row is updated
				checkUpdateSetRequestCurrentNameNil(),
				checkUpdateSetRequestNewNameNil(),
				checkName(""),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update description",
			changeFuncs: []changeHostSetFunc{changeDescription("foo")},
			version:     2,
			fieldMask:   []string{"description"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateSetRequestCurrentDescriptionNil(),
				checkUpdateSetRequestNewDescription("foo"),
				checkDescription("foo"),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update description to same",
			changeFuncs: []changeHostSetFunc{changeDescription("")},
			version:     2,
			fieldMask:   []string{"description"},
			wantCheckFuncs: []checkFunc{
				checkVersion(2), // Version remains same even though row is updated
				checkUpdateSetRequestCurrentDescriptionNil(),
				checkUpdateSetRequestNewDescriptionNil(),
				checkDescription(""),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update preferred endpoints",
			changeFuncs: []changeHostSetFunc{changePreferredEndpoints([]string{"cidr:10.0.0.0/24"})},
			version:     2,
			fieldMask:   []string{"PreferredEndpoints"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateSetRequestCurrentPreferredEndpointsNil(),
				checkUpdateSetRequestNewPreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				checkPreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update preferred endpoints to same",
			changeFuncs: []changeHostSetFunc{changePreferredEndpoints(nil)},
			version:     2,
			fieldMask:   []string{"PreferredEndpoints"},
			wantCheckFuncs: []checkFunc{
				checkVersion(2),
				checkUpdateSetRequestCurrentPreferredEndpointsNil(),
				checkUpdateSetRequestNewPreferredEndpointsNil(),
				checkPreferredEndpoints(nil),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(0),
			},
		},
		{
			name: "update attributes (add)",
			changeFuncs: []changeHostSetFunc{changeAttributes(map[string]interface{}{
				"baz": "qux",
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateSetRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				checkUpdateSetRequestNewAttributes(map[string]interface{}{
					"foo": "bar",
					"baz": "qux",
				}),
				checkAttributes(map[string]interface{}{
					"foo": "bar",
					"baz": "qux",
				}),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (overwrite)",
			changeFuncs: []changeHostSetFunc{changeAttributes(map[string]interface{}{
				"foo": "baz",
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateSetRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				checkUpdateSetRequestNewAttributes(map[string]interface{}{
					"foo": "baz",
				}),
				checkAttributes(map[string]interface{}{
					"foo": "baz",
				}),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (null)",
			changeFuncs: []changeHostSetFunc{changeAttributes(map[string]interface{}{
				"foo": nil,
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateSetRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				checkUpdateSetRequestNewAttributes(map[string]interface{}{}),
				checkAttributes(map[string]interface{}{}),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update attributes (full null)",
			changeFuncs: []changeHostSetFunc{changeAttributesNil()},
			version:     2,
			fieldMask:   []string{"attributes"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateSetRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				checkUpdateSetRequestNewAttributes(map[string]interface{}{}),
				checkAttributes(map[string]interface{}{}),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (combined)",
			changeFuncs: []changeHostSetFunc{changeAttributes(map[string]interface{}{
				"a":   "b",
				"foo": "baz",
			})},
			version:   2,
			fieldMask: []string{"attributes.a", "attributes.foo"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateSetRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				checkUpdateSetRequestNewAttributes(map[string]interface{}{
					"a":   "b",
					"foo": "baz",
				}),
				checkAttributes(map[string]interface{}{
					"a":   "b",
					"foo": "baz",
				}),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update name and preferred endpoints",
			changeFuncs: []changeHostSetFunc{
				changePreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				changeName("foo"),
			},
			version:   2,
			fieldMask: []string{"name", "PreferredEndpoints"},
			wantCheckFuncs: []checkFunc{
				checkVersion(3),
				checkUpdateSetRequestCurrentNameNil(),
				checkUpdateSetRequestNewName("foo"),
				checkName("foo"),
				checkUpdateSetRequestCurrentPreferredEndpointsNil(),
				checkUpdateSetRequestNewPreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				checkPreferredEndpoints([]string{"cidr:10.0.0.0/24"}),
				checkUpdateSetRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				checkNumUpdated(1),
				checkVerifySetOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
	}

	// Create a host that will be verified as belonging to the created set below.
	testHostExternIdPrefix := "test-host-external-id"
	testHosts := make([]*Host, 3)
	for i := 0; i <= 2; i++ {
		testHosts[i] = TestHost(t, dbConn, testCatalog.PublicId, fmt.Sprintf("%s-%d", testHostExternIdPrefix, i))
	}

	// Finally define a function for bringing the test subject host
	// set.
	setupHostSet := func(t *testing.T, ctx context.Context) *HostSet {
		t.Helper()
		require := require.New(t)

		set := TestSet(t, dbConn, dbKmsCache, sched, testCatalog, testPluginMap)
		// Set some (default) attributes on our test set
		set.Attributes = mustMarshal(map[string]interface{}{
			"foo": "bar",
		})

		numSetsUpdated, err := dbRW.Update(ctx, set, []string{"attributes"}, []string{})
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

		return set
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)
			origSet := setupHostSet(t, ctx)

			pluginMap := testPluginMap
			if tt.withEmptyPluginMap {
				pluginMap = make(map[string]plgpb.HostPluginServiceClient)
			}
			pluginError = tt.withPluginError
			t.Cleanup(func() { pluginError = nil })
			repo, err := NewRepository(dbRW, dbRW, dbKmsCache, sched, pluginMap)
			require.NoError(err)
			require.NotNil(repo)

			workingSet := origSet.clone()
			for _, cf := range tt.changeFuncs {
				workingSet = cf(workingSet)
			}

			scopeId := testCatalog.ScopeId
			if tt.withScopeId != nil {
				scopeId = *tt.withScopeId
			}

			var gotHosts []*Host
			var gotPlugin *hostplugin.Plugin
			gotSet, gotHosts, gotPlugin, gotNumUpdated, err = repo.UpdateSet(ctx, scopeId, workingSet, tt.version, tt.fieldMask)
			t.Cleanup(func() { gotOnUpdateCallCount = 0 })
			if tt.wantIsErr != 0 {
				require.Equal(db.NoRowsAffected, gotNumUpdated)
				require.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			require.Equal(1, gotOnUpdateCallCount)
			t.Cleanup(func() { gotOnUpdateSetRequest = nil })

			// Quick assertion that the set is not nil and that the plugin
			// ID in the catalog referenced by the set matches the plugin
			// ID in the returned plugin.
			require.NotNil(gotSet)
			require.NotNil(gotPlugin)
			assert.Equal(testCatalog.PublicId, gotSet.CatalogId)
			assert.Equal(testCatalog.PluginId, gotPlugin.PublicId)

			// Also assert that the hosts returned by the request are the ones that belong to the set
			wantHostMap := make(map[string]string, len(testHosts))
			for _, h := range testHosts {
				wantHostMap[h.PublicId] = h.ExternalId
			}
			gotHostMap := make(map[string]string, len(gotHosts))
			for _, h := range gotHosts {
				gotHostMap[h.PublicId] = h.ExternalId
			}
			assert.Equal(wantHostMap, gotHostMap)

			// Perform checks
			for _, check := range tt.wantCheckFuncs {
				check(t, ctx)
			}
		})
	}
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
	plg := hostplg.TestPlugin(t, conn, "lookup")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(&TestPluginServer{}),
	}

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	hostSet := TestSet(t, conn, kms, sched, catalog, map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(&TestPluginServer{
			ListHostsFn: func(ctx context.Context, req *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error) {
				require.NotEmpty(t, req.GetSets())
				require.NotNil(t, req.GetCatalog())
				return &plgpb.ListHostsResponse{}, nil
			},
		}),
	})
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
			repo, err := NewRepository(rw, rw, kms, sched, plgm)
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
	plg := hostplg.TestPlugin(t, conn, "endpoints")

	hostlessCatalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(&TestPluginServer{}),
	}

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	hostSet10 := TestSet(t, conn, kms, sched, catalog, plgm, WithPreferredEndpoints([]string{"cidr:10.0.0.1/24"}))
	hostSet192 := TestSet(t, conn, kms, sched, catalog, plgm, WithPreferredEndpoints([]string{"cidr:192.168.0.1/24"}))
	hostSet100 := TestSet(t, conn, kms, sched, catalog, plgm, WithPreferredEndpoints([]string{"cidr:100.100.100.100/24"}))
	hostlessSet := TestSet(t, conn, kms, sched, hostlessCatalog, plgm)

	h1 := TestHost(t, conn, catalog.GetPublicId(), "test", withIpAddresses([]string{"10.0.0.5", "192.168.0.5"}))
	TestSetMembers(t, conn, hostSet10.GetPublicId(), []*Host{h1})
	TestSetMembers(t, conn, hostSet192.GetPublicId(), []*Host{h1})
	TestSetMembers(t, conn, hostSet100.GetPublicId(), []*Host{h1})

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
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms, sched, plgm)
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

func TestRepository_ListSets(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "list")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(&TestPluginServer{}),
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
		opts      []host.Option
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
			repo, err := NewRepository(rw, rw, kms, sched, plgm)
			assert.NoError(err)
			require.NotNil(repo)
			got, gotPlg, err := repo.ListSets(context.Background(), tt.in, tt.opts...)
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
		})
	}
}

func TestRepository_ListSets_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	sched := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "listlimit")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(&TestPluginServer{}),
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
		listOpts []host.Option
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
			name:     "With negative repo limit",
			repoOpts: []host.Option{host.WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:     "With List limit",
			listOpts: []host.Option{host.WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []host.Option{host.WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:     "With repo smaller than list limit",
			repoOpts: []host.Option{host.WithLimit(2)},
			listOpts: []host.Option{host.WithLimit(6)},
			wantLen:  6,
		},
		{
			name:     "With repo larger than list limit",
			repoOpts: []host.Option{host.WithLimit(6)},
			listOpts: []host.Option{host.WithLimit(2)},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms, sched, plgm, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, gotPlg, err := repo.ListSets(context.Background(), hostSets[0].CatalogId, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
			assert.Empty(cmp.Diff(plg, gotPlg, protocmp.Transform()))
		})
	}
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
	plg := hostplg.TestPlugin(t, conn, "create")

	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): NewWrappingPluginClient(TestPluginServer{OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
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
			repo, err := NewRepository(rw, rw, kms, sched, plgm)
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
