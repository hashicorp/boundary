package plugin

import (
	"context"
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
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestRepository_CreateSet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "create", "create")

	var pluginReceivedAttrs *structpb.Struct
	plgm := map[string]plgpb.HostPluginServiceServer{
		plg.GetPublicId(): &TestPluginServer{OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
			pluginReceivedAttrs = req.GetSet().GetAttributes()
			return &plgpb.OnCreateSetResponse{}, nil
		}},
	}

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
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
			repo, err := NewRepository(rw, rw, kms, plgm)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateSet(context.Background(), prj.GetPublicId(), tt.in, tt.opts...)
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

			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms, plgm)
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

		got, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assert.True(strings.HasPrefix(got.GetPublicId(), HostSetPrefix))
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.GetName())
		assert.Equal(in.Description, got.GetDescription())
		assert.Equal(got.GetCreateTime(), got.GetUpdateTime())

		got2, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-catalogs", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms, plgm)
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
		got, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assert.True(strings.HasPrefix(got.GetPublicId(), HostSetPrefix))
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.GetName())
		assert.Equal(in.Description, got.GetDescription())
		assert.Equal(got.GetCreateTime(), got.GetUpdateTime())

		in2.CatalogId = catalogB.PublicId
		got2, err := repo.CreateSet(context.Background(), prj.GetPublicId(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assert.True(strings.HasPrefix(got.GetPublicId(), HostSetPrefix))
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.GetName())
		assert.Equal(in2.Description, got2.GetDescription())
		assert.Equal(got2.GetCreateTime(), got2.GetUpdateTime())
	})
}

func TestRepository_LookupSet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "lookup", "lookup")
	plgm := map[string]plgpb.HostPluginServiceServer{
		plg.GetPublicId(): &TestPluginServer{},
	}

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	hostSet := TestSet(t, conn, kms, catalog, map[string]plgpb.HostPluginServiceServer{
		plg.GetPublicId(): &TestPluginServer{},
	})
	hostSetId, err := newHostSetId(ctx, plg.GetIdPrefix())
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
			repo, err := NewRepository(rw, rw, kms, plgm)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupSet(ctx, tt.in)
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

func TestRepository_ListSets(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "list", "list")
	plgm := map[string]plgpb.HostPluginServiceServer{
		plg.GetPublicId(): &TestPluginServer{},
	}
	catalogA := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	catalogB := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())

	hostSets := []*HostSet{
		TestSet(t, conn, kms, catalogA, plgm),
		TestSet(t, conn, kms, catalogA, plgm),
		TestSet(t, conn, kms, catalogA, plgm),
	}

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
			repo, err := NewRepository(rw, rw, kms, plgm)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListSets(context.Background(), tt.in, tt.opts...)
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
		})
	}
}

func TestRepository_ListSets_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "listlimit", "listlimit")
	plgm := map[string]plgpb.HostPluginServiceServer{
		plg.GetPublicId(): &TestPluginServer{},
	}
	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	count := 10
	var hostSets []*HostSet
	for i := 0; i < count; i++ {
		hostSets = append(hostSets, TestSet(t, conn, kms, catalog, plgm))
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
			repo, err := NewRepository(rw, rw, kms, plgm, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListSets(context.Background(), hostSets[0].CatalogId, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}
