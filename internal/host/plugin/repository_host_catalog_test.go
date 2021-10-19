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
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
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

func assertPluginBasedPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want 1 '_' in PublicId, got %d in %q", len(parts), actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
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

	assert := assert.New(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms, plgm)
	assert.NoError(err)
	assert.NotNil(repo)

	tests := []struct {
		name    string
		id      string
		pluginResponse func(*plgpb.OnDeleteCatalogRequest) error
		want    int
		wantErr errors.Code
	}{
		{
			name: "found",
			id:   cat.GetPublicId(),
			pluginResponse: func(req *plgpb.OnDeleteCatalogRequest) error {
				assert.Equal(cat.GetPublicId(), req.GetCatalog().GetId())
				return nil
			},
			want: 1,
		},
		{
			name: "ignore error",
			id:   cat2.GetPublicId(),
			pluginResponse: func(req *plgpb.OnDeleteCatalogRequest) error {
				assert.Equal(cat2.GetPublicId(), req.GetCatalog().GetId())
				return fmt.Errorf("This is a test error")
			},
			want: 1,
		},
		{
			name: "not-found",
			id:   badId,
			pluginResponse: func(req *plgpb.OnDeleteCatalogRequest) error {
				assert.Fail("Should not call the plugin when catalog isn't found")
				return nil
			},
			want: 0,
		},
		{
			name:    "bad-public-id",
			id:      "",
			pluginResponse: func(req *plgpb.OnDeleteCatalogRequest) error {
				assert.Fail("Should not call the plugin for a bad id")
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
				return nil, tt.pluginResponse(request)
			}
			got, err := repo.DeleteCatalog(context.Background(), tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, got, "row count")
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