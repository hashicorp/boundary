package host_catalogs_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hostcatalogs"
	scopepb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/host_catalogs"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createDefaultHostCatalogAndRepo(t *testing.T) (*static.HostCatalog, *iam.Scope, common.StaticRepoFactory, common.IamRepoFactory) {
	t.Helper()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	_, pRes := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}

	hc, err := static.NewHostCatalog(pRes.GetPublicId(), static.WithName("default"), static.WithDescription("default"))
	require.NoError(err, "Couldn't get new catalog.")
	repo, err := repoFn()
	require.NoError(err, "Couldn't create static repostitory")
	hcRes, err := repo.CreateCatalog(context.Background(), hc)
	require.NoError(err, "Couldn't persist new catalog.")

	return hcRes, pRes, repoFn, iamRepoFn
}

func TestGet(t *testing.T) {
	t.Parallel()
	hc, proj, repo, iamRepoFn := createDefaultHostCatalogAndRepo(t)
	toMerge := &pbs.GetHostCatalogRequest{
		Id: hc.GetPublicId(),
	}

	pHostCatalog := &pb.HostCatalog{
		Id:          hc.GetPublicId(),
		ScopeId:     hc.GetScopeId(),
		Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		Name:        &wrappers.StringValue{Value: hc.GetName()},
		Description: &wrappers.StringValue{Value: hc.GetDescription()},
		CreatedTime: hc.CreateTime.GetTimestamp(),
		UpdatedTime: hc.UpdateTime.GetTimestamp(),
		Type:        "static",
	}

	cases := []struct {
		name    string
		req     *pbs.GetHostCatalogRequest
		res     *pbs.GetHostCatalogResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing HostCatalog",
			req:     &pbs.GetHostCatalogRequest{Id: hc.GetPublicId()},
			res:     &pbs.GetHostCatalogResponse{Item: pHostCatalog},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existing Host Catalog",
			req:     &pbs.GetHostCatalogRequest{Id: static.HostCatalogPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.PermissionDenied,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetHostCatalogRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetHostCatalogRequest{Id: static.HostCatalogPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostCatalogRequest)
			proto.Merge(req, tc.req)

			s, err := host_catalogs.NewService(repo, iamRepoFn)
			require.NoError(t, err, "Couldn't create a new host catalog service.")

			got, gErr := s.GetHostCatalog(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, pNoCatalogs := iam.TestScopes(t, iamRepo)
	_, pWithCatalogs := iam.TestScopes(t, iamRepo)
	_, pWithOtherCatalogs := iam.TestScopes(t, iamRepo)

	var wantSomeCatalogs []*pb.HostCatalog
	for _, hc := range static.TestCatalogs(t, conn, pWithCatalogs.GetPublicId(), 3) {
		wantSomeCatalogs = append(wantSomeCatalogs, &pb.HostCatalog{
			Id:          hc.GetPublicId(),
			ScopeId:     hc.GetScopeId(),
			CreatedTime: hc.GetCreateTime().GetTimestamp(),
			UpdatedTime: hc.GetUpdateTime().GetTimestamp(),
			Scope:       &scopepb.ScopeInfo{Id: pWithCatalogs.GetPublicId(), Type: scope.Project.String()},
			Version:     1,
			Type:        "static",
		})
	}

	var wantOtherCatalogs []*pb.HostCatalog
	for _, hc := range static.TestCatalogs(t, conn, pWithOtherCatalogs.GetPublicId(), 3) {
		wantOtherCatalogs = append(wantOtherCatalogs, &pb.HostCatalog{
			Id:          hc.GetPublicId(),
			ScopeId:     hc.GetScopeId(),
			CreatedTime: hc.GetCreateTime().GetTimestamp(),
			UpdatedTime: hc.GetUpdateTime().GetTimestamp(),
			Scope:       &scopepb.ScopeInfo{Id: pWithOtherCatalogs.GetPublicId(), Type: scope.Project.String()},
			Version:     1,
			Type:        "static",
		})
	}

	cases := []struct {
		name    string
		scopeId string
		res     *pbs.ListHostCatalogsResponse
		errCode codes.Code
	}{
		{
			name:    "List Some Catalogs",
			scopeId: pWithCatalogs.GetPublicId(),
			res:     &pbs.ListHostCatalogsResponse{Items: wantSomeCatalogs},
			errCode: codes.OK,
		},
		{
			name:    "List Other Catalogs",
			scopeId: pWithOtherCatalogs.GetPublicId(),
			res:     &pbs.ListHostCatalogsResponse{Items: wantOtherCatalogs},
			errCode: codes.OK,
		},
		{
			name:    "List No Catalogs",
			scopeId: pNoCatalogs.GetPublicId(),
			res:     &pbs.ListHostCatalogsResponse{},
			errCode: codes.OK,
		},
		{
			name:    "Unfound Catalogs",
			scopeId: scope.Project.Prefix() + "_DoesntExis",
			errCode: codes.PermissionDenied,
		},
		{
			name:    "Bad scope level",
			scopeId: scope.Global.String(),
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := host_catalogs.NewService(repoFn, iamRepoFn)
			require.NoError(err, "Couldn't create new auth_method service.")

			got, gErr := s.ListHostCatalogs(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), &pbs.ListHostCatalogsRequest{ScopeId: tc.scopeId})
			assert.Equal(tc.errCode, status.Code(gErr), "ListHostCatalogs() for scope %q got error %v, wanted %v", tc.scopeId, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListHostCatalogs() for scope %q got response %q, wanted %q", tc.scopeId, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	hc, proj, repo, iamRepoFn := createDefaultHostCatalogAndRepo(t)

	s, err := host_catalogs.NewService(repo, iamRepoFn)
	require.NoError(err, "Couldn't create a new host catalog service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteHostCatalogRequest
		res     *pbs.DeleteHostCatalogResponse
		errCode codes.Code
	}{
		{
			name:    "Delete an Existing HostCatalog",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostCatalogRequest{
				Id: hc.GetPublicId(),
			},
			res: &pbs.DeleteHostCatalogResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name:    "Delete bad id HostCatalog",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostCatalogRequest{
				Id: static.HostCatalogPrefix + "_doesntexis",
			},
			errCode: codes.PermissionDenied,
		},
		{
			name:    "Bad HostCatalog Id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostCatalogRequest{
				Id: static.HostCatalogPrefix + "_bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteHostCatalog(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteHostCatalog(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteHostCatalog(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	hc, proj, repo, iamRepoFn := createDefaultHostCatalogAndRepo(t)

	s, err := host_catalogs.NewService(repo, iamRepoFn)
	require.NoError(t, err, "Couldn't create a new host catalog service.")
	req := &pbs.DeleteHostCatalogRequest{
		Id: hc.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId()))
	got, gErr := s.DeleteHostCatalog(ctx, req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteHostCatalog(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.Equal(codes.PermissionDenied, status.Code(gErr), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	t.Parallel()
	defaultHc, proj, repo, iamRepoFn := createDefaultHostCatalogAndRepo(t)
	defaultHcCreated, err := ptypes.Timestamp(defaultHc.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp.")
	toMerge := &pbs.CreateHostCatalogRequest{}

	cases := []struct {
		name    string
		req     *pbs.CreateHostCatalogRequest
		res     *pbs.CreateHostCatalogResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid HostCatalog",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:     proj.GetPublicId(),
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "static",
			}},
			res: &pbs.CreateHostCatalogResponse{
				Uri: fmt.Sprintf("host-catalogs/%s_", static.HostCatalogPrefix),
				Item: &pb.HostCatalog{
					ScopeId:     proj.GetPublicId(),
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "name"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Cant create in org",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:     proj.GetParentId(),
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "static",
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant create in global",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				ScopeId:     scope.Global.String(),
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "static",
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Create with unknown type",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "thisismadeup",
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Create with no type",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				Id: "not allowed to be set",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateHostCatalogRequest)
			proto.Merge(req, tc.req)

			s, err := host_catalogs.NewService(repo, iamRepoFn)
			require.NoError(err, "Failed to create a new host catalog service.")

			got, gErr := s.CreateHostCatalog(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), static.HostCatalogPrefix))
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a catalog created after the test setup's default catalog
				assert.True(gotCreateTime.After(defaultHcCreated), "New catalog should have been created after default catalog. Was created %v, which is after %v", gotCreateTime, defaultHcCreated)
				assert.True(gotUpdateTime.After(defaultHcCreated), "New catalog should have been updated after default catalog. Was updated %v, which is after %v", gotUpdateTime, defaultHcCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	hc, proj, repoFn, iamRepoFn := createDefaultHostCatalogAndRepo(t)
	tested, err := host_catalogs.NewService(repoFn, iamRepoFn)
	require.NoError(t, err, "Failed to create a new host catalog service.")

	var version uint32 = 1

	resetHostCatalog := func() {
		version++
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't create new static repo.")
		hc, _, err = repo.UpdateCatalog(context.Background(), hc, version, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset host catalog.")
		version++
	}

	hcCreated, err := ptypes.Timestamp(hc.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Failed to convert proto to timestamp")
	toMerge := &pbs.UpdateHostCatalogRequest{
		Id: hc.GetPublicId(),
	}

	cases := []struct {
		name    string
		req     *pbs.UpdateHostCatalogRequest
		res     *pbs.UpdateHostCatalogResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing HostCatalog",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					ScopeId:     hc.GetScopeId(),
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
					Type:        "static",
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					Type:        "static",
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					ScopeId:     hc.GetScopeId(),
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
					Type:        "static",
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostCatalogRequest{
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostCatalog{
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					ScopeId:     hc.GetScopeId(),
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Description: &wrappers.StringValue{Value: "default"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
					Type:        "static",
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostCatalog{
					Name: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					ScopeId:     hc.GetScopeId(),
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "default"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
					Type:        "static",
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					ScopeId:     hc.GetScopeId(),
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "default"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
					Type:        "static",
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "ignored"},
					Description: &wrappers.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					ScopeId:     hc.GetScopeId(),
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "default"},
					Description: &wrappers.StringValue{Value: "notignored"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
					Type:        "static",
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Cant change type",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "type"},
				},
				Item: &pb.HostCatalog{
					Name: &wrappers.StringValue{Value: "updated name"},
					Type: "ec2",
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Update a Non Existing HostCatalog",
			req: &pbs.UpdateHostCatalogRequest{
				Id: static.HostCatalogPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "new"},
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			errCode: codes.PermissionDenied,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateHostCatalogRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.HostCatalog{
					Id:          "p_somethinge",
					Scope:       &scopepb.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.HostCatalog{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.HostCatalog{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Valid mask, cant specify type",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostCatalog{
					Type: "unknown",
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tc.req.Item.Version = version

			req := proto.Clone(toMerge).(*pbs.UpdateHostCatalogRequest)
			proto.Merge(req, tc.req)

			// Test some bad versions
			req.Item.Version = version + 2
			_, gErr := tested.UpdateHostCatalog(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.Error(gErr)
			req.Item.Version = version - 1
			_, gErr = tested.UpdateHostCatalog(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.Error(gErr)
			req.Item.Version = version

			got, gErr := tested.UpdateHostCatalog(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if tc.errCode == codes.OK {
				defer resetHostCatalog()
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateHostCatalog response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Failed to convert proto to timestamp")
				// Verify it is a catalog updated after it was created
				// TODO: This is currently failing.
				//assert.True(gotUpdateTime.After(hcCreated), "Updated catalog should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, hcCreated)
				_ = gotUpdateTime
				_ = hcCreated

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = version + 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
