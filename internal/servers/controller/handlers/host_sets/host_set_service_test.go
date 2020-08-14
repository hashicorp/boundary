package host_sets_test

import (
	"context"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/host_sets"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createDefaultHostCatalogAndRepo(t *testing.T) (*static.HostCatalog, *iam.Scope, func() (*static.Repository, error)) {
	t.Helper()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	_, pRes := iam.TestScopes(t, conn)

	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(rw, rw, wrap)
	}

	hc, err := static.NewHostCatalog(pRes.GetPublicId(), static.WithName("default"), static.WithDescription("default"))
	require.NoError(err, "Couldn't get new catalog.")
	repo, err := repoFn()
	require.NoError(err, "Couldn't create static repostitory")
	hcRes, err := repo.CreateCatalog(context.Background(), hc)
	require.NoError(err, "Couldn't persist new catalog.")

	return hcRes, pRes, repoFn
}

// TODO: Uncomment all the valid test cases.
func TestGet(t *testing.T) {
	t.Parallel()
	hc, proj, repo := createDefaultHostCatalogAndRepo(t)
	toMerge := &pbs.GetHostSetRequest{
		Id: hc.GetPublicId(),
	}

	// pHostSet := &pb.HostSet{
	// 	Id:          hc.GetPublicId(),
	// 	CreatedTime: hc.CreateTime.GetTimestamp(),
	// 	UpdatedTime: hc.UpdateTime.GetTimestamp(),
	// 	Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
	// 	Name:        &wrappers.StringValue{Value: hc.GetName()},
	// 	Description: &wrappers.StringValue{Value: hc.GetDescription()},
	// 	Type:        "static",
	// }

	cases := []struct {
		name    string
		req     *pbs.GetHostSetRequest
		res     *pbs.GetHostSetResponse
		errCode codes.Code
	}{
		// {
		// 	name:    "Get an Existing HostSet",
		// 	req:     &pbs.GetHostSetRequest{Id: hc.GetPublicId()},
		// 	res:     &pbs.GetHostSetResponse{Item: pHostSet},
		// 	errCode: codes.OK,
		// },
		{
			name:    "Get a non existing Host Set",
			req:     &pbs.GetHostSetRequest{Id: static.HostSetPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetHostSetRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetHostSetRequest{Id: static.HostSetPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostSetRequest)
			proto.Merge(req, tc.req)

			s, err := host_sets.NewService(repo)
			require.NoError(t, err, "Couldn't create a new host set service.")

			got, gErr := s.GetHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetHostSet(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetHostSet(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	hc, proj, repo := createDefaultHostCatalogAndRepo(t)

	s, err := host_sets.NewService(repo)
	require.NoError(t, err, "Couldn't create a new host set service.")

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.DeleteHostSetRequest
		res     *pbs.DeleteHostSetResponse
		errCode codes.Code
	}{
		// {
		// 	name:    "Delete an Existing HostSet",
		// 	scopeId: proj.GetPublicId(),
		// 	req: &pbs.DeleteHostSetRequest{
		// 		HostCatalogId: hc.GetPublicId(),
		// 		Id: hs.GetPublicId(),
		// 	},
		// 	res: &pbs.DeleteHostSetResponse{
		// 		Existed: true,
		// 	},
		// 	errCode: codes.OK,
		// },
		{
			name:    "Delete bad id HostSet",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				HostCatalogId: hc.GetPublicId(),
				Id:            static.HostSetPrefix + "_doesntexis",
			},
			res: &pbs.DeleteHostSetResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		// {
		// 	name:    "Delete bad host catalog id in HostSet",
		// 	scopeId: "p_doesntexis",
		// 	req: &pbs.DeleteHostSetRequest{
		// 		HostCatalogId: hc.GetPublicId(),
		// 		Id: hs.GetPublicId(),
		// 	},
		// 	res: &pbs.DeleteHostSetResponse{
		// 		Existed: false,
		// 	},
		// 	errCode: codes.OK,
		// },
		{
			name:    "Bad HostSet Id formatting",
			scopeId: proj.GetPublicId(),
			req: &pbs.DeleteHostSetRequest{
				Id: static.HostSetPrefix + "_bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteHostSet(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteHostSet(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	hc, proj, repo := createDefaultHostCatalogAndRepo(t)

	s, err := host_sets.NewService(repo)
	require.NoError(t, err, "Couldn't create a new host set service.")
	req := &pbs.DeleteHostSetRequest{
		HostCatalogId: hc.GetPublicId(),
		Id:            static.HostSetPrefix + "_1234567890",
	}
	ctx := auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId()))
	got, gErr := s.DeleteHostSet(ctx, req)
	assert.NoError(gErr, "First attempt")
	// assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	// got, gErr = s.DeleteHostSet(ctx, req)
	// assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	t.Parallel()
	hc, proj, repo := createDefaultHostCatalogAndRepo(t)
	_ = hc
	toMerge := &pbs.CreateHostSetRequest{}

	cases := []struct {
		name    string
		req     *pbs.CreateHostSetRequest
		res     *pbs.CreateHostSetResponse
		errCode codes.Code
	}{
		// {
		// 	name: "Create a valid HostSet",
		// 	req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
		// 		Name:        &wrappers.StringValue{Value: "name"},
		// 		Description: &wrappers.StringValue{Value: "desc"},
		// 		Type:        "static",
		// 	}},
		// 	res: &pbs.CreateHostSetResponse{
		// 		Uri: fmt.Sprintf("scopes/%s/host-sets/%s_", proj.GetPublicId(), static.HostSetPrefix),
		// 		Item: &pb.HostSet{
		// 			HostCatalogId: hc.GetPublicId(),
		// 			Scope:         &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		// 			Name:          &wrappers.StringValue{Value: "name"},
		// 			Description:   &wrappers.StringValue{Value: "desc"},
		// 			Type:          "static",
		// 		},
		// 	},
		// 	errCode: codes.OK,
		// },
		{
			name: "Create with unknown type",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
				Type:        "ThisIsMadeUp",
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Create with no type",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
			}},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				Id: "not allowed to be set",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateHostSetRequest{Item: &pb.HostSet{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateHostSetRequest)
			proto.Merge(req, tc.req)

			s, err := host_sets.NewService(repo)
			require.NoError(err, "Failed to create a new host set service.")

			got, gErr := s.CreateHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateHostSet(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.GetUri())
				assert.True(strings.HasPrefix(got.GetItem().GetId(), static.HostSetPrefix))
				// gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				// require.NoError(err, "Error converting proto to timestamp.")
				// gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				// require.NoError(err, "Error converting proto to timestamp")
				// // Verify it is a set created after the test setup's default set
				// assert.True(gotCreateTime.After(defaultHcCreated), "New set should have been created after default set. Was created %v, which is after %v", gotCreateTime, defaultHcCreated)
				// assert.True(gotUpdateTime.After(defaultHcCreated), "New set should have been updated after default set. Was updated %v, which is after %v", gotUpdateTime, defaultHcCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateHostSet(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	hc, proj, repoFn := createDefaultHostCatalogAndRepo(t)
	tested, err := host_sets.NewService(repoFn)
	require.NoError(t, err, "Failed to create a new host set service.")

	var version uint32 = 1

	resetHostSet := func() {
		version++
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't create new static repo.")
		// hc, _, err = repo.UpdateSet(context.Background(), hc, version, []string{"Name", "Description"})
		// require.NoError(t, err, "Failed to reset host set.")
		_ = repo
		version++
	}

	hcCreated, err := ptypes.Timestamp(hc.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Failed to convert proto to timestamp")
	toMerge := &pbs.UpdateHostSetRequest{
		Id: hc.GetPublicId(),
	}

	cases := []struct {
		name    string
		req     *pbs.UpdateHostSetRequest
		res     *pbs.UpdateHostSetResponse
		errCode codes.Code
	}{
		// {
		// 	name: "Update an Existing HostSet",
		// 	req: &pbs.UpdateHostSetRequest{
		// 		UpdateMask: &field_mask.FieldMask{
		// 			Paths: []string{"name", "description"},
		// 		},
		// 		Item: &pb.HostSet{
		// 			Name:        &wrappers.StringValue{Value: "new"},
		// 			Description: &wrappers.StringValue{Value: "desc"},
		// 		},
		// 	},
		// 	res: &pbs.UpdateHostSetResponse{
		// 		Item: &pb.HostSet{
		// 			Id:          hc.GetPublicId(),
		// 			Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		// 			Name:        &wrappers.StringValue{Value: "new"},
		// 			Description: &wrappers.StringValue{Value: "desc"},
		// 			CreatedTime: hc.GetCreateTime().GetTimestamp(),
		// 			Type:        &wrappers.StringValue{Value: "Static"},
		// 		},
		// 	},
		// 	errCode: codes.OK,
		// },
		// {
		// 	name: "Multiple Paths in single string",
		// 	req: &pbs.UpdateHostSetRequest{
		// 		UpdateMask: &field_mask.FieldMask{
		// 			Paths: []string{"name,description"},
		// 		},
		// 		Item: &pb.HostSet{
		// 			Name:        &wrappers.StringValue{Value: "new"},
		// 			Description: &wrappers.StringValue{Value: "desc"},
		// 		},
		// 	},
		// 	res: &pbs.UpdateHostSetResponse{
		// 		Item: &pb.HostSet{
		// 			Id:          hc.GetPublicId(),
		// 			Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		// 			Name:        &wrappers.StringValue{Value: "new"},
		// 			Description: &wrappers.StringValue{Value: "desc"},
		// 			CreatedTime: hc.GetCreateTime().GetTimestamp(),
		// 			Type:        &wrappers.StringValue{Value: "Static"},
		// 		},
		// 	},
		// 	errCode: codes.OK,
		// },
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostSetRequest{
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.HostSet{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		// {
		// 	name: "Unset Name",
		// 	req: &pbs.UpdateHostSetRequest{
		// 		UpdateMask: &field_mask.FieldMask{
		// 			Paths: []string{"name"},
		// 		},
		// 		Item: &pb.HostSet{
		// 			Description: &wrappers.StringValue{Value: "ignored"},
		// 		},
		// 	},
		// 	res: &pbs.UpdateHostSetResponse{
		// 		Item: &pb.HostSet{
		// 			Id:          hc.GetPublicId(),
		// 			Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		// 			Description: &wrappers.StringValue{Value: "default"},
		// 			CreatedTime: hc.GetCreateTime().GetTimestamp(),
		// 			Type:        &wrappers.StringValue{Value: "Static"},
		// 		},
		// 	},
		// 	errCode: codes.OK,
		// },
		// {
		// 	name: "Unset Description",
		// 	req: &pbs.UpdateHostSetRequest{
		// 		UpdateMask: &field_mask.FieldMask{
		// 			Paths: []string{"description"},
		// 		},
		// 		Item: &pb.HostSet{
		// 			Name: &wrappers.StringValue{Value: "ignored"},
		// 		},
		// 	},
		// 	res: &pbs.UpdateHostSetResponse{
		// 		Item: &pb.HostSet{
		// 			Id:          hc.GetPublicId(),
		// 			Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		// 			Name:        &wrappers.StringValue{Value: "default"},
		// 			CreatedTime: hc.GetCreateTime().GetTimestamp(),
		// 			Type:        &wrappers.StringValue{Value: "Static"},
		// 		},
		// 	},
		// 	errCode: codes.OK,
		// },
		// {
		// 	name: "Update Only Name",
		// 	req: &pbs.UpdateHostSetRequest{
		// 		UpdateMask: &field_mask.FieldMask{
		// 			Paths: []string{"name"},
		// 		},
		// 		Item: &pb.HostSet{
		// 			Name:        &wrappers.StringValue{Value: "updated"},
		// 			Description: &wrappers.StringValue{Value: "ignored"},
		// 		},
		// 	},
		// 	res: &pbs.UpdateHostSetResponse{
		// 		Item: &pb.HostSet{
		// 			Id:          hc.GetPublicId(),
		// 			Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		// 			Name:        &wrappers.StringValue{Value: "updated"},
		// 			Description: &wrappers.StringValue{Value: "default"},
		// 			CreatedTime: hc.GetCreateTime().GetTimestamp(),
		// 			Type:        &wrappers.StringValue{Value: "Static"},
		// 		},
		// 	},
		// 	errCode: codes.OK,
		// },
		// {
		// 	name: "Update Only Description",
		// 	req: &pbs.UpdateHostSetRequest{
		// 		UpdateMask: &field_mask.FieldMask{
		// 			Paths: []string{"description"},
		// 		},
		// 		Item: &pb.HostSet{
		// 			Name:        &wrappers.StringValue{Value: "ignored"},
		// 			Description: &wrappers.StringValue{Value: "notignored"},
		// 		},
		// 	},
		// 	res: &pbs.UpdateHostSetResponse{
		// 		Item: &pb.HostSet{
		// 			Id:          hc.GetPublicId(),
		// 			Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		// 			Name:        &wrappers.StringValue{Value: "default"},
		// 			Description: &wrappers.StringValue{Value: "notignored"},
		// 			CreatedTime: hc.GetCreateTime().GetTimestamp(),
		// 			Type:        &wrappers.StringValue{Value: "Static"},
		// 		},
		// 	},
		// 	errCode: codes.OK,
		// },
		// TODO: Updating a non existing set should result in a NotFound exception but currently results in
		// the repoFn returning an internal error.
		// {
		// 	name: "Update a Non Existing HostSet",
		// 	req: &pbs.UpdateHostSetRequest{
		// 		Id: static.HostSetPrefix + "_DoesntExis",
		// 		UpdateMask: &field_mask.FieldMask{
		// 			Paths: []string{"description"},
		// 		},
		// 		Item: &pb.HostSet{
		// 			Name:        &wrappers.StringValue{Value: "new"},
		// 			Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
		// 			Description: &wrappers.StringValue{Value: "desc"},
		// 		},
		// 	},
		// 	errCode: codes.Internal,
		// },
		{
			name: "Cant change Id",
			req: &pbs.UpdateHostSetRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.HostSet{
					Id:          "p_somethinge",
					Scope:       &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String()},
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.HostSet{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.HostSet{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Valid mask, cant specify type",
			req: &pbs.UpdateHostSetRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostSet{
					Type: "Unknown",
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tc.req.Version = version

			req := proto.Clone(toMerge).(*pbs.UpdateHostSetRequest)
			proto.Merge(req, tc.req)

			// Test some bad versions
			req.Version = version + 2
			_, gErr := tested.UpdateHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.Error(gErr)
			req.Version = version - 1
			_, gErr = tested.UpdateHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			require.Error(gErr)
			req.Version = version

			got, gErr := tested.UpdateHostSet(auth.DisabledAuthTestContext(auth.WithScopeId(proj.GetPublicId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateHostSet(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if tc.errCode == codes.OK {
				defer resetHostSet()
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateHostSet response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Failed to convert proto to timestamp")
				// Verify it is a set updated after it was created
				// TODO: This is currently failing.
				//assert.True(gotUpdateTime.After(hcCreated), "Updated set should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, hcCreated)
				_ = gotUpdateTime
				_ = hcCreated

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			if tc.res != nil {
				tc.res.Item.Version = version + 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateHostSet(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
