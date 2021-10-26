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
	"github.com/hashicorp/boundary/internal/plugin/host"
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	testDuplicateCatalogNameOrgScope     = "duplicate-catalog-name-org-scope"
	testDuplicateCatalogNameProjectScope = "duplicate-catalog-name-project-scope"
)

func TestRepository_CreateCatalog(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
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
			repo, err := NewRepository(rw, rw, kmsCache, plgm)
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
		repo, err := NewRepository(rw, rw, kms, plgm)
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
		repo, err := NewRepository(rw, rw, kms, plgm)
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
	state := testRepositoryStateSetup(t, ctx)
	tests := []struct {
		name               string
		withEmptyPluginMap bool
		withPluginError    error
		catalogOpts        []testSetCatalogOption
		version            uint32
		fieldMask          []string
		wantChecks         []testRepositoryHostCatalogCheck
		wantIsErr          errors.Code
	}{
		{
			name:        "nil catalog",
			catalogOpts: []testSetCatalogOption{withNilCatalog()},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "nil embedded catalog",
			catalogOpts: []testSetCatalogOption{withNilEmbeddedCatalog()},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "missing public id",
			catalogOpts: []testSetCatalogOption{withPublicId("")},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:        "missing scope id",
			catalogOpts: []testSetCatalogOption{withScopeId("")},
			wantIsErr:   errors.InvalidParameter,
		},
		{
			name:      "empty field mask",
			fieldMask: nil, // Should be testing on len
			wantIsErr: errors.EmptyFieldMask,
		},
		{
			name:        "bad catalog id",
			catalogOpts: []testSetCatalogOption{withPublicId("badid")},
			fieldMask:   []string{"name"},
			wantIsErr:   errors.RecordNotFound,
		},
		{
			name:               "plugin lookup error",
			withEmptyPluginMap: true,
			fieldMask:          []string{"name"},
			wantIsErr:          errors.InvalidParameter,
		},
		{
			name:            "plugin invocation error",
			withPluginError: errors.New(context.Background(), errors.Internal, "TestRepository_UpdateCatalog/plugin_invocation_error", "test plugin error"),
			fieldMask:       []string{"name"},
			wantIsErr:       errors.Internal,
		},
		{
			name:        "update name (duplicate, same scope)",
			catalogOpts: []testSetCatalogOption{withName(testDuplicateCatalogNameProjectScope)},
			version:     2,
			fieldMask:   []string{"name"},
			wantIsErr:   errors.NotUnique,
		},
		{
			name:        "update name",
			catalogOpts: []testSetCatalogOption{withName("foo")},
			version:     2,
			fieldMask:   []string{"name"},
			wantChecks: []testRepositoryHostCatalogCheck{
				withCheckVersion(3),
				withCheckUpdateCatalogRequestCurrentName(""),
				withCheckUpdateCatalogRequestNewName("foo"),
				withCheckName("foo"),
				withCheckSecrets(map[string]interface{}{
					"one": "two",
				}),
				withCheckNumCatalogsUpdated(1),
				withCheckNumSecretsUpdated(0),
				withVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update name (duplicate, different scope)",
			catalogOpts: []testSetCatalogOption{withName(testDuplicateCatalogNameOrgScope)},
			version:     2,
			fieldMask:   []string{"name"},
			wantChecks: []testRepositoryHostCatalogCheck{
				withCheckVersion(3),
				withCheckUpdateCatalogRequestCurrentName(""),
				withCheckUpdateCatalogRequestNewName(testDuplicateCatalogNameOrgScope),
				withCheckName(testDuplicateCatalogNameOrgScope),
				withCheckSecrets(map[string]interface{}{
					"one": "two",
				}),
				withCheckNumCatalogsUpdated(1),
				withCheckNumSecretsUpdated(0),
				withVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "update description",
			catalogOpts: []testSetCatalogOption{withDescription("foo")},
			version:     2,
			fieldMask:   []string{"description"},
			wantChecks: []testRepositoryHostCatalogCheck{
				withCheckVersion(3),
				withCheckUpdateCatalogRequestCurrentDescription(""),
				withCheckUpdateCatalogRequestNewDescription("foo"),
				withCheckDescription("foo"),
				withCheckSecrets(map[string]interface{}{
					"one": "two",
				}),
				withCheckNumCatalogsUpdated(1),
				withCheckNumSecretsUpdated(0),
				withVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (add)",
			catalogOpts: []testSetCatalogOption{withAttributes(map[string]interface{}{
				"baz": "qux",
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantChecks: []testRepositoryHostCatalogCheck{
				withCheckVersion(3),
				withCheckUpdateCatalogRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				withCheckUpdateCatalogRequestNewAttributes(map[string]interface{}{
					"foo": "bar",
					"baz": "qux",
				}),
				withCheckAttributes(map[string]interface{}{
					"foo": "bar",
					"baz": "qux",
				}),
				withCheckSecrets(map[string]interface{}{
					"one": "two",
				}),
				withCheckNumCatalogsUpdated(1),
				withCheckNumSecretsUpdated(0),
				withVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (overwrite)",
			catalogOpts: []testSetCatalogOption{withAttributes(map[string]interface{}{
				"foo": "baz",
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantChecks: []testRepositoryHostCatalogCheck{
				withCheckVersion(3),
				withCheckUpdateCatalogRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				withCheckUpdateCatalogRequestNewAttributes(map[string]interface{}{
					"foo": "baz",
				}),
				withCheckAttributes(map[string]interface{}{
					"foo": "baz",
				}),
				withCheckSecrets(map[string]interface{}{
					"one": "two",
				}),
				withCheckNumCatalogsUpdated(1),
				withCheckNumSecretsUpdated(0),
				withVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update attributes (null)",
			catalogOpts: []testSetCatalogOption{withAttributes(map[string]interface{}{
				"foo": nil,
			})},
			version:   2,
			fieldMask: []string{"attributes"},
			wantChecks: []testRepositoryHostCatalogCheck{
				withCheckVersion(3),
				withCheckUpdateCatalogRequestCurrentAttributes(map[string]interface{}{
					"foo": "bar",
				}),
				withCheckUpdateCatalogRequestNewAttributes(map[string]interface{}{}),
				withCheckAttributes(map[string]interface{}{}),
				withCheckSecrets(map[string]interface{}{
					"one": "two",
				}),
				withCheckNumCatalogsUpdated(1),
				withCheckNumSecretsUpdated(0),
				withVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name: "update secrets",
			catalogOpts: []testSetCatalogOption{withSecrets(map[string]interface{}{
				"three": "four",
			})},
			version:   2,
			fieldMask: []string{"secrets"},
			wantChecks: []testRepositoryHostCatalogCheck{
				withCheckVersion(2), // Secret update does not update host catalog record itself
				withCheckUpdateCatalogRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				withCheckUpdateCatalogRequestSecrets(map[string]interface{}{
					"three": "four",
				}),
				withCheckSecrets(map[string]interface{}{
					"three": "four",
				}),
				withCheckNumCatalogsUpdated(0),
				withCheckNumSecretsUpdated(1),
				withVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
		{
			name:        "delete secrets",
			catalogOpts: []testSetCatalogOption{withSecrets(map[string]interface{}{})},
			version:     2,
			fieldMask:   []string{"secrets"},
			wantChecks: []testRepositoryHostCatalogCheck{
				withCheckVersion(2), // Secret update does not update host catalog record itself
				withCheckUpdateCatalogRequestPersistedSecrets(map[string]interface{}{
					"one": "two",
				}),
				withCheckUpdateCatalogRequestSecrets(map[string]interface{}{}),
				withCheckSecretsDeleted(),
				withCheckNumCatalogsUpdated(0),
				withCheckNumSecretsUpdated(1),
				withVerifyCatalogOplog(oplog.OpType_OP_TYPE_UPDATE),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			origCat, cleanup := state.testRepositorySetupHostCatalog(t, ctx)
			defer cleanup()

			pluginMap := state.PluginMap
			if tt.withEmptyPluginMap {
				pluginMap = make(map[string]plgpb.HostPluginServiceClient)
			}
			state.PluginError = tt.withPluginError
			defer func() { state.PluginError = nil }()
			repo, err := NewRepository(state.DBRW, state.DBRW, state.KmsCache, pluginMap)
			require.NoError(err)
			require.NotNil(repo)

			workingCat := testSetCatalog(origCat, tt.catalogOpts...)
			got := new(testRepositoryHostCatalogCheckDetails)
			got.Catalog, got.NumCatalogsUpdated, got.NumSecretsUpdated, err = repo.UpdateCatalog(ctx, workingCat, tt.version, tt.fieldMask)
			if tt.wantIsErr != 0 {
				require.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			got.OnUpdateCatalogRequest = state.GotOnUpdateCatalogRequest

			// Perform checks
			for _, check := range tt.wantChecks {
				check(t, ctx, state, got)
			}
		})
	}
}

func TestRepository_LookupCatalog(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
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
			repo, err := NewRepository(rw, rw, kms, plgm)
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
	plg := hostplg.TestPlugin(t, conn, "test")
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &WrappingPluginClient{Server: &TestPluginServer{}},
	}
	repo, err := NewRepository(rw, rw, kms, plgm)
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
	repo, err := NewRepository(rw, rw, kms, plgm)
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
			repo, err := NewRepository(rw, rw, kms, plgm)
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

// testSetCatalogOption represents an option that is set on a catalog
// repository function request, typically UpdateCatalog.
type testSetCatalogOption func(c *HostCatalog) *HostCatalog

// withPublicId sets the public id in a HostCatalog to the supplied
// id.
func withPublicId(id string) testSetCatalogOption {
	return func(c *HostCatalog) *HostCatalog {
		c.PublicId = id
		return c
	}
}

// withScopeId sets the scope id in a HostCatalog to the supplied id.
func withScopeId(id string) testSetCatalogOption {
	return func(c *HostCatalog) *HostCatalog {
		c.ScopeId = id
		return c
	}
}

// withName sets the name in a HostCatalog to the supplied name.
func withName(name string) testSetCatalogOption {
	return func(c *HostCatalog) *HostCatalog {
		c.Name = name
		return c
	}
}

// withDescription sets the name in a HostCatalog to the supplied
// desc.
func withDescription(desc string) testSetCatalogOption {
	return func(c *HostCatalog) *HostCatalog {
		c.Description = desc
		return c
	}
}

// withAttributes sets the attributes in a HostCatalog to the
// supplied map.
//
// The map must be able to be marshaled to a structpb.Struct or this
// function will panic.
func withAttributes(in map[string]interface{}) testSetCatalogOption {
	return func(c *HostCatalog) *HostCatalog {
		c.Attributes = mustMarshal(in)
		return c
	}
}

// withSecrets sets the secrets in a HostCatalog to the supplied map.
//
// The map must be able to be marshaled to a structpb.Struct or this
// function will panic.
func withSecrets(in map[string]interface{}) testSetCatalogOption {
	return func(c *HostCatalog) *HostCatalog {
		c.Secrets = mustStruct(in)
		return c
	}
}

// withNilCatalog sets the entire catalog to nil. This should be the
// only option in a particular test case or any other options will
// likely panic.
func withNilCatalog() testSetCatalogOption {
	return func(_ *HostCatalog) *HostCatalog {
		return nil
	}
}

// withNilEmbeddedCatalog sets the embedded catalog to nil. This
// should be the only option in a particular test case or any other
// options will likely panic.
func withNilEmbeddedCatalog() testSetCatalogOption {
	return func(c *HostCatalog) *HostCatalog {
		c.HostCatalog = nil
		return c
	}
}

// testSetCatalog creates a new in memory HostCatalog with various fields set
// and only those fields. This is intended for use in UpdateCatalog.
func testSetCatalog(c *HostCatalog, opts ...testSetCatalogOption) *HostCatalog {
	c = &HostCatalog{
		HostCatalog: &store.HostCatalog{
			PublicId: c.PublicId,
			ScopeId:  c.ScopeId,
		},
	}
	for _, opt := range opts {
		c = opt(c)
	}

	return c
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

// testRepositoryHostCatalogCheckDetails describes test data that's
// received during select repository methods. This is used with the
// check type below (testRepositoryHostCatalogCheck) to test
// various repository functions.
type testRepositoryHostCatalogCheckDetails struct {
	Catalog                *HostCatalog
	OnUpdateCatalogRequest *plgpb.OnUpdateCatalogRequest
	NumCatalogsUpdated     int
	NumSecretsUpdated      int
}

// testRepositoryHostCatalogCheck represents a specific repository
// function check.
type testRepositoryHostCatalogCheck func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails)

// withCheckName checks the returned Catalog's name.
func withCheckName(want string) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Equal(want, got.Catalog.Name)
	}
}

// withCheckDescription checks the returned Catalog's description.
func withCheckDescription(want string) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Equal(want, got.Catalog.Description)
	}
}

// withCheckVersion checks the returned Catalog's version.
func withCheckVersion(want uint32) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Equal(want, got.Catalog.Version)
	}
}

// withCheckAttributes checks the returned Catalog's attributes.
func withCheckAttributes(want map[string]interface{}) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		require := require.New(t)
		st := &structpb.Struct{}
		require.NoError(proto.Unmarshal(got.Catalog.Attributes, st))
		assert.Empty(cmp.Diff(mustStruct(want), st, protocmp.Transform()))
	}
}

// withCheckSecrets checks the returned Catalog's secrets.
func withCheckSecrets(want map[string]interface{}) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		require := require.New(t)

		cSecret := allocHostCatalogSecret()
		err := state.DBRW.LookupWhere(ctx, &cSecret, "catalog_id=?", got.Catalog.GetPublicId())
		require.NoError(err)
		require.Empty(cSecret.Secret)
		require.NotEmpty(cSecret.CtSecret)

		dbWrapper, err := state.KmsCache.GetWrapper(ctx, got.Catalog.GetScopeId(), kms.KeyPurposeDatabase)
		require.NoError(err)
		require.NoError(cSecret.decrypt(ctx, dbWrapper))

		st := &structpb.Struct{}
		require.NoError(proto.Unmarshal(cSecret.Secret, st))
		assert.Empty(cmp.Diff(mustStruct(want), st, protocmp.Transform()))
	}
}

// withCheckSecretsDeleted checks the returned Catalog's secrets to
// make sure they are gonne.
func withCheckSecretsDeleted() testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)

		cSecret := allocHostCatalogSecret()
		err := state.DBRW.LookupWhere(ctx, &cSecret, "catalog_id=?", got.Catalog.GetPublicId())
		assert.Error(err)
		assert.True(errors.IsNotFoundError(err))
	}
}

// withCheckUpdateCatalogRequestCurrentName checks the
// OnUpdateCatalogRequest sent by OnUpdateCatalog for the current
// catalog's name.
func withCheckUpdateCatalogRequestCurrentName(want string) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Equal(wrapperspb.String(want), got.OnUpdateCatalogRequest.CurrentCatalog.Name)
	}
}

// withCheckUpdateCatalogRequestNewName checks the
// OnUpdateCatalogRequest sent by OnUpdateCatalog for the new
// catalog's name.
func withCheckUpdateCatalogRequestNewName(want string) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Equal(wrapperspb.String(want), got.OnUpdateCatalogRequest.NewCatalog.Name)
	}
}

// withCheckUpdateCatalogRequestCurrentDescription checks the
// OnUpdateCatalogRequest sent by OnUpdateCatalog for the current
// catalog's description.
func withCheckUpdateCatalogRequestCurrentDescription(want string) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Equal(wrapperspb.String(want), got.OnUpdateCatalogRequest.CurrentCatalog.Description)
	}
}

// withCheckUpdateCatalogRequestNewDescription checks the
// OnUpdateCatalogRequest sent by OnUpdateCatalog for the new
// catalog's description.
func withCheckUpdateCatalogRequestNewDescription(want string) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Equal(wrapperspb.String(want), got.OnUpdateCatalogRequest.NewCatalog.Description)
	}
}

// withCheckUpdateCatalogRequestCurrentAttributes checks the
// OnUpdateCatalogRequest sent by OnUpdateCatalog for the current
// catalog's attributes.
func withCheckUpdateCatalogRequestCurrentAttributes(want map[string]interface{}) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Empty(cmp.Diff(mustStruct(want), got.OnUpdateCatalogRequest.CurrentCatalog.Attributes, protocmp.Transform()))
	}
}

// withCheckUpdateCatalogRequestNewAttributes checks the
// OnUpdateCatalogRequest sent by OnUpdateCatalog for the new
// catalog's attributes.
func withCheckUpdateCatalogRequestNewAttributes(want map[string]interface{}) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Empty(cmp.Diff(mustStruct(want), got.OnUpdateCatalogRequest.NewCatalog.Attributes, protocmp.Transform()))
	}
}

// withCheckUpdateCatalogRequestPersisted checks the
// OnUpdateCatalogRequest sent by OnUpdateCatalog for the persisted
// state.
func withCheckUpdateCatalogRequestPersistedSecrets(want map[string]interface{}) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Empty(cmp.Diff(mustStruct(want), got.OnUpdateCatalogRequest.Persisted.Secrets, protocmp.Transform()))
	}
}

// withCheckUpdateCatalogRequestSecrets checks the
// OnUpdateCatalogRequest sent by OnUpdateCatalog for the new
// catalog's secrets.
//
// It also asserts that the current catalogs's secrets field is nil;
// this is never set.
func withCheckUpdateCatalogRequestSecrets(want map[string]interface{}) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Empty(cmp.Diff(mustStruct(want), got.OnUpdateCatalogRequest.NewCatalog.Secrets, protocmp.Transform()))
		// Ensure that the current catalog's secrets value is always zero
		assert.Zero(got.OnUpdateCatalogRequest.CurrentCatalog.Secrets)
	}
}

// withCheckNumCatalogsUpdated asserts the number of catalogs updated
// in UpdateCatalog.
func withCheckNumCatalogsUpdated(want int) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Equal(want, got.NumCatalogsUpdated)
	}
}

// withCheckNumSecretsUpdated asserts the number of secrets updated
// in UpdateCatalog.
func withCheckNumSecretsUpdated(want int) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.Equal(want, got.NumSecretsUpdated)
	}
}

// withVerifyCatalogOplog asserts that an entry was written for the
// catalog.
func withVerifyCatalogOplog(op oplog.OpType) testRepositoryHostCatalogCheck {
	return func(t *testing.T, ctx context.Context, state *testRepositoryState, got *testRepositoryHostCatalogCheckDetails) {
		t.Helper()
		assert := assert.New(t)
		assert.NoError(
			db.TestVerifyOplog(
				t,
				state.DBRW,
				got.Catalog.PublicId,
				db.WithOperation(op),
				db.WithCreateNotBefore(10*time.Second),
			),
		)
	}
}

// testRepositoryState represents the complex state that needs to be
// set up during repository tests.
type testRepositoryState struct {
	DBConn                      *db.DB
	DBRW                        *db.Db
	Wrapper                     wrapping.Wrapper
	KmsCache                    *kms.Kms
	OrgScope                    *iam.Scope
	ProjectScope                *iam.Scope
	Plugin                      *host.Plugin
	PluginMap                   map[string]plgpb.HostPluginServiceClient
	PluginError                 error
	GotOnUpdateCatalogRequest   *plgpb.OnUpdateCatalogRequest
	ExistingOrgScopeCatalog     *HostCatalog
	ExistingProjectScopeCatalog *HostCatalog
}

// testRepositoryStateSetup does initial setup of a repository state
// for a test and returns a testRepositoryState.
func testRepositoryStateSetup(t *testing.T, ctx context.Context) *testRepositoryState {
	t.Helper()

	s := new(testRepositoryState)
	// DB setup
	s.setupDB(t)
	// KMS setup
	s.setupKMS(t)
	// IAM scope setup
	s.setupScopes(t)
	// Plugin setup
	s.setupPlugins(t)
	// Setup existing catalogs
	s.setupExistingCatalogs(t, ctx)

	return s
}

// setupDB takes care of initial DB-related setup tasks.
func (s *testRepositoryState) setupDB(t *testing.T) {
	t.Helper()
	s.DBConn, _ = db.TestSetup(t, "postgres")
	s.DBRW = db.New(s.DBConn)
	s.Wrapper = db.TestWrapper(t)
}

// setupKMS takes care of initial KMS-related setup tasks.
func (s *testRepositoryState) setupKMS(t *testing.T) {
	t.Helper()
	s.Wrapper = db.TestWrapper(t)
	s.KmsCache = kms.TestKms(t, s.DBConn, s.Wrapper)
}

// setupScopes sets up a project scope for the state.
func (s *testRepositoryState) setupScopes(t *testing.T) {
	t.Helper()
	s.OrgScope, s.ProjectScope = iam.TestScopes(t, iam.TestRepo(t, s.DBConn, s.Wrapper))
}

// setupPlugins configures a plugin for the repository state.
//
// This also patches received data for various hook functions over to
// fields in the state - example: GotOnUpdateCatalogRequest. These
// fields currently do not have any concurrency built in, which is
// important to note when running tests; as such, they can't be run
// in parallel.
func (s *testRepositoryState) setupPlugins(t *testing.T) {
	t.Helper()
	s.Plugin = hostplg.TestPlugin(t, s.DBConn, "test")
	s.PluginMap = map[string]plgpb.HostPluginServiceClient{
		s.Plugin.GetPublicId(): &WrappingPluginClient{
			Server: &TestPluginServer{
				OnUpdateCatalogFn: func(_ context.Context, req *plgpb.OnUpdateCatalogRequest) (*plgpb.OnUpdateCatalogResponse, error) {
					s.GotOnUpdateCatalogRequest = req
					return &plgpb.OnUpdateCatalogResponse{Persisted: &plgpb.HostCatalogPersisted{Secrets: req.GetNewCatalog().GetSecrets()}}, s.PluginError
				},
			},
		},
	}
}

// setupExistingCatalogs sets up some existing host catalogs for the
// state that can be used to test 2 scenarios:
//
// * Changing or creating a catalog in the same scope to a duplicate
// name.
//
// * Changing or creating a catalog to/with a name that is shared by
// another catalog, but in a different scope.
func (s *testRepositoryState) setupExistingCatalogs(t *testing.T, ctx context.Context) {
	t.Helper()
	require := require.New(t)
	var err error

	// Org scope
	s.ExistingOrgScopeCatalog = TestCatalog(t, s.DBConn, s.OrgScope.PublicId, s.Plugin.GetPublicId())
	s.ExistingOrgScopeCatalog.Name = testDuplicateCatalogNameOrgScope
	numCatUpdated, err := s.DBRW.Update(ctx, s.ExistingOrgScopeCatalog, []string{"name"}, []string{})
	require.NoError(err)
	require.Equal(1, numCatUpdated)

	// Project scope
	s.ExistingProjectScopeCatalog = TestCatalog(t, s.DBConn, s.ProjectScope.PublicId, s.Plugin.GetPublicId())
	s.ExistingProjectScopeCatalog.Name = testDuplicateCatalogNameProjectScope
	numCatUpdated, err = s.DBRW.Update(ctx, s.ExistingProjectScopeCatalog, []string{"name"}, []string{})
	require.NoError(err)
	require.Equal(1, numCatUpdated)
}

// testRepositorySetupHostCatalog returns a new configured host
// catalog for the test repository. The second return value is a
// cleanup function that can be called to delete the catalog.
func (s *testRepositoryState) testRepositorySetupHostCatalog(t *testing.T, ctx context.Context) (*HostCatalog, func()) {
	t.Helper()
	require := require.New(t)

	cat := TestCatalog(t, s.DBConn, s.ProjectScope.PublicId, s.Plugin.GetPublicId())
	// Set some (default) attributes on our test catalog
	cat.Attributes = mustMarshal(map[string]interface{}{
		"foo": "bar",
	})

	numCatUpdated, err := s.DBRW.Update(ctx, cat, []string{"attributes"}, []string{})
	require.NoError(err)
	require.Equal(1, numCatUpdated)

	// Set up some secrets
	cSecretProto := mustStruct(map[string]interface{}{
		"one": "two",
	})
	cSecret, err := newHostCatalogSecret(ctx, cat.GetPublicId(), cSecretProto)
	require.NoError(err)
	scopeWrapper, err := s.KmsCache.GetWrapper(ctx, cat.GetScopeId(), kms.KeyPurposeDatabase)
	require.NoError(err)
	require.NoError(cSecret.encrypt(ctx, scopeWrapper))
	cSecretQ, cSecretV := cSecret.upsertQuery()
	secretsUpdated, err := s.DBRW.Exec(ctx, cSecretQ, cSecretV)
	require.NoError(err)
	require.Equal(1, secretsUpdated)

	cleanupFunc := func() {
		t.Helper()
		assert := assert.New(t)
		n, err := s.DBRW.Delete(ctx, cat)
		assert.NoError(err)
		assert.Equal(1, n)
	}

	return cat, cleanupFunc
}
