package plugin

import (
	"context"
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
	plg := hostplg.TestPlugin(t, conn, "create")
	unimplementedPlugin := hostplg.TestPlugin(t, conn, "unimplemented")

	var pluginReceivedAttrs *structpb.Struct
	plgm := new(hostplugin.PluginMap)
	plgm.Set(plg.GetPublicId(), &TestPluginServer{OnCreateSetFn: func(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
		pluginReceivedAttrs = req.GetSet().GetAttributes()
		return &plgpb.OnCreateSetResponse{}, nil
	}})
	plgm.Set(unimplementedPlugin.GetPublicId(), &plgpb.UnimplementedHostPluginServiceServer{})

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
			repo, err := NewRepository(rw, rw, kms, plgm)
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

func TestRepository_LookupSet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "lookup")
	plgm := new(hostplugin.PluginMap)
	plgm.Set(plg.GetPublicId(), &TestPluginServer{})

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	hostSet := TestSet(t, conn, kms, catalog, plgm)
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
			repo, err := NewRepository(rw, rw, kms, plgm)
			assert.NoError(err)
			require.NotNil(repo)
			got, _, _, err := repo.LookupSet(ctx, tt.in)
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
	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "endpoints")

	hostlessCatalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	plgm := new(hostplugin.PluginMap)
	plgm.Set(plg.GetPublicId(), &TestPluginServer{
		ListHostsFn: func(_ context.Context, req *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error) {
			if req.Catalog.GetId() == hostlessCatalog.GetPublicId() {
				return &plgpb.ListHostsResponse{}, nil
			}
			var setIds []string
			for _, set := range req.GetSets() {
				setIds = append(setIds, set.GetId())
			}
			return &plgpb.ListHostsResponse{Hosts: []*plgpb.ListHostsResponseHost{
				{
					SetIds:      setIds,
					ExternalId:  "test",
					IpAddresses: []string{"10.0.0.5", "192.168.0.5"},
					DnsNames:    nil,
				},
			}}, nil
		},
	},
	)

	catalog := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	hostSet10 := TestSet(t, conn, kms, catalog, plgm, WithPreferredEndpoints([]string{"cidr:10.0.0.1/24"}))
	hostSet192 := TestSet(t, conn, kms, catalog, plgm, WithPreferredEndpoints([]string{"cidr:192.168.0.1/24"}))
	hostSet100 := TestSet(t, conn, kms, catalog, plgm, WithPreferredEndpoints([]string{"cidr:100.100.100.100/24"}))
	hostlessSet := TestSet(t, conn, kms, hostlessCatalog, plgm)

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
			repo, err := NewRepository(rw, rw, kms, plgm)
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

			// TODO: Remove this once we no longer persist all host lookup calls
			//   when retrieving the endpoints.
			for _, ep := range got {
				h := allocHost()
				h.PublicId = ep.HostId
				require.NoError(rw.LookupByPublicId(ctx, h))

				assert.Equal(uint32(1), h.Version)
				assert.Equal(ep.HostId, h.PublicId)
				assert.Equal(ep.Address, h.Address)
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

	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "list")
	plgm := new(hostplugin.PluginMap)
	plgm.Set(plg.GetPublicId(), &TestPluginServer{})
	catalogA := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())
	catalogB := TestCatalog(t, conn, prj.PublicId, plg.GetPublicId())

	hostSets := []*HostSet{
		TestSet(t, conn, kms, catalogA, plgm),
		TestSet(t, conn, kms, catalogA, plgm),
		TestSet(t, conn, kms, catalogA, plgm),
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
			repo, err := NewRepository(rw, rw, kms, plgm)
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

	_, prj := iam.TestScopes(t, iamRepo)
	plg := hostplg.TestPlugin(t, conn, "listlimit")
	plgm := new(hostplugin.PluginMap)
	plgm.Set(plg.GetPublicId(), &TestPluginServer{})

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
			got, gotPlg, err := repo.ListSets(context.Background(), hostSets[0].CatalogId, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
			assert.Empty(cmp.Diff(plg, gotPlg, protocmp.Transform()))
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
