package groups_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/watchtower/internal/auth"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/groups"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/groups"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Creates an org scoped group and a project scoped group.
func createDefaultGroupsAndRepo(t *testing.T) (*iam.Group, *iam.Group, func() (*iam.Repository, error)) {
	t.Helper()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}

	o, p := iam.TestScopes(t, conn)
	og := iam.TestGroup(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	pg := iam.TestGroup(t, conn, p.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	return og, pg, repoFn
}

func TestGet(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	og, pg, repo := createDefaultGroupsAndRepo(t)
	toMerge := &pbs.GetGroupRequest{
		ScopeId: og.GetScopeId(),
		Id:      og.GetPublicId(),
	}

	wantOrgGroup := &pb.Group{
		Id:          og.GetPublicId(),
		Name:        &wrapperspb.StringValue{Value: og.GetName()},
		Description: &wrapperspb.StringValue{Value: og.GetDescription()},
		CreatedTime: og.CreateTime.GetTimestamp(),
		UpdatedTime: og.UpdateTime.GetTimestamp(),
	}

	wantProjGroup := &pb.Group{
		Id:          pg.GetPublicId(),
		Name:        &wrapperspb.StringValue{Value: pg.GetName()},
		Description: &wrapperspb.StringValue{Value: pg.GetDescription()},
		CreatedTime: pg.CreateTime.GetTimestamp(),
		UpdatedTime: pg.UpdateTime.GetTimestamp(),
	}

	cases := []struct {
		name    string
		req     *pbs.GetGroupRequest
		res     *pbs.GetGroupResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing Group",
			req:     &pbs.GetGroupRequest{Id: og.GetPublicId()},
			res:     &pbs.GetGroupResponse{Item: wantOrgGroup},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existant Group",
			req:     &pbs.GetGroupRequest{Id: iam.GroupPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetGroupRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetGroupRequest{Id: iam.GroupPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Project Scoped Get an Existing Group",
			req:     &pbs.GetGroupRequest{Id: pg.GetPublicId(), ScopeId: pg.GetScopeId()},
			res:     &pbs.GetGroupResponse{Item: wantProjGroup},
			errCode: codes.OK,
		},
		{
			name:    "Project Scoped Get a non existant Group",
			req:     &pbs.GetGroupRequest{Id: iam.GroupPrefix + "_DoesntExis", ScopeId: pg.GetScopeId()},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Project Scoped Wrong id prefix",
			req:     &pbs.GetGroupRequest{Id: "j_1234567890", ScopeId: pg.GetScopeId()},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Project Scoped space in id",
			req:     &pbs.GetGroupRequest{Id: iam.GroupPrefix + "_1 23456789", ScopeId: pg.GetScopeId()},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetGroupRequest)
			proto.Merge(req, tc.req)

			s, err := groups.NewService(repo)
			require.NoError(err, "Couldn't create new group service.")

			got, gErr := s.GetGroup(auth.DisabledAuthContext(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetGroup(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetGroup(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}
	oNoGroups, pWithGroups := iam.TestScopes(t, conn)
	oWithGroups, pNoGroups := iam.TestScopes(t, conn)
	var wantOrgGroups []*pb.Group
	var wantProjGroups []*pb.Group
	for i := 0; i < 10; i++ {
		og := iam.TestGroup(t, conn, oWithGroups.GetPublicId())
		wantOrgGroups = append(wantOrgGroups, &pb.Group{
			Id:          og.GetPublicId(),
			CreatedTime: og.GetCreateTime().GetTimestamp(),
			UpdatedTime: og.GetUpdateTime().GetTimestamp(),
		})
		pg := iam.TestGroup(t, conn, pWithGroups.GetPublicId())
		wantProjGroups = append(wantProjGroups, &pb.Group{
			Id:          pg.GetPublicId(),
			CreatedTime: pg.GetCreateTime().GetTimestamp(),
			UpdatedTime: pg.GetUpdateTime().GetTimestamp(),
		})
	}

	cases := []struct {
		name    string
		req     *pbs.ListGroupsRequest
		res     *pbs.ListGroupsResponse
		errCode codes.Code
	}{
		{
			name:    "List Many Group",
			req:     &pbs.ListGroupsRequest{ScopeId: oWithGroups.GetPublicId()},
			res:     &pbs.ListGroupsResponse{Items: wantOrgGroups},
			errCode: codes.OK,
		},
		{
			name:    "List No Groups",
			req:     &pbs.ListGroupsRequest{ScopeId: oNoGroups.GetPublicId()},
			res:     &pbs.ListGroupsResponse{},
			errCode: codes.OK,
		},
		{
			name:    "Invalid Org Id",
			req:     &pbs.ListGroupsRequest{ScopeId: scope.Org.Prefix() + "_this is invalid"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		// TODO: When an org doesn't exist, we should return a 404 instead of an empty list.
		{
			name:    "Unfound Org",
			req:     &pbs.ListGroupsRequest{ScopeId: scope.Org.Prefix() + "_DoesntExis"},
			res:     &pbs.ListGroupsResponse{},
			errCode: codes.OK,
		},
		{
			name:    "List Many Project Group",
			req:     &pbs.ListGroupsRequest{ScopeId: pWithGroups.GetPublicId()},
			res:     &pbs.ListGroupsResponse{Items: wantProjGroups},
			errCode: codes.OK,
		},
		{
			name:    "List No Project Groups",
			req:     &pbs.ListGroupsRequest{ScopeId: pNoGroups.GetPublicId()},
			res:     &pbs.ListGroupsResponse{},
			errCode: codes.OK,
		},
		{
			name:    "Invalid Project Id",
			req:     &pbs.ListGroupsRequest{ScopeId: scope.Project.Prefix() + "_this is invalid"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		// TODO: When an org doesn't exist, we should return a 404 instead of an empty list.
		{
			name:    "Unfound Project",
			req:     &pbs.ListGroupsRequest{ScopeId: scope.Project.Prefix() + "_DoesntExis"},
			res:     &pbs.ListGroupsResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := groups.NewService(repoFn)
			require.NoError(err, "Couldn't create new group service.")

			got, gErr := s.ListGroups(auth.DisabledAuthContext(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "ListGroups(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "ListGroups(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	require := require.New(t)
	og, pg, repo := createDefaultGroupsAndRepo(t)

	s, err := groups.NewService(repo)
	require.NoError(err, "Error when getting new group service.")

	cases := []struct {
		name    string
		req     *pbs.DeleteGroupRequest
		res     *pbs.DeleteGroupResponse
		errCode codes.Code
	}{
		{
			name: "Delete an Existing Group",
			req: &pbs.DeleteGroupRequest{
				ScopeId: og.GetScopeId(),
				Id:      og.GetPublicId(),
			},
			res: &pbs.DeleteGroupResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad group id",
			req: &pbs.DeleteGroupRequest{
				ScopeId: og.GetScopeId(),
				Id:      iam.GroupPrefix + "_doesntexis",
			},
			res: &pbs.DeleteGroupResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad org id",
			req: &pbs.DeleteGroupRequest{
				ScopeId: "o_doesntexis",
				Id:      og.GetPublicId(),
			},
			res: &pbs.DeleteGroupResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad org formatting",
			req: &pbs.DeleteGroupRequest{
				ScopeId: "bad_format",
				Id:      og.GetPublicId(),
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Group Id formatting",
			req: &pbs.DeleteGroupRequest{
				ScopeId: og.GetScopeId(),
				Id:      "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Project Scoped Delete an Existing Group",
			req: &pbs.DeleteGroupRequest{
				ScopeId: pg.GetScopeId(),
				Id:      pg.GetPublicId(),
			},
			res: &pbs.DeleteGroupResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Project Scoped Delete bad group id",
			req: &pbs.DeleteGroupRequest{
				ScopeId: pg.GetScopeId(),
				Id:      iam.GroupPrefix + "_doesntexis",
			},
			res: &pbs.DeleteGroupResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Project Scoped Delete bad project id",
			req: &pbs.DeleteGroupRequest{
				ScopeId: scope.Project.Prefix() + "_doesntexis",
				Id:      pg.GetPublicId(),
			},
			res: &pbs.DeleteGroupResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad project formatting",
			req: &pbs.DeleteGroupRequest{
				ScopeId: "bad_format",
				Id:      pg.GetPublicId(),
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteGroup(auth.DisabledAuthContext(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteGroup(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	og, pg, repo := createDefaultGroupsAndRepo(t)

	s, err := groups.NewService(repo)
	require.NoError(err, "Error when getting new group service")
	req := &pbs.DeleteGroupRequest{
		ScopeId: og.GetScopeId(),
		Id:      og.GetPublicId(),
	}
	ctx := auth.DisabledAuthContext()
	got, gErr := s.DeleteGroup(ctx, req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteGroup(ctx, req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")

	projReq := &pbs.DeleteGroupRequest{
		ScopeId: pg.GetScopeId(),
		Id:      pg.GetPublicId(),
	}
	got, gErr = s.DeleteGroup(ctx, projReq)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteGroup(ctx, projReq)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	require := require.New(t)
	defaultOGroup, defaultPGroup, repo := createDefaultGroupsAndRepo(t)
	defaultCreated, err := ptypes.Timestamp(defaultOGroup.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp.")
	toMerge := &pbs.CreateGroupRequest{
		ScopeId: defaultOGroup.GetScopeId(),
	}

	cases := []struct {
		name    string
		req     *pbs.CreateGroupRequest
		res     *pbs.CreateGroupResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid Group",
			req: &pbs.CreateGroupRequest{Item: &pb.Group{
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateGroupResponse{
				Uri: fmt.Sprintf("orgs/%s/groups/%s_", defaultOGroup.GetScopeId(), iam.GroupPrefix),
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Create a valid Project Scoped Group",
			req: &pbs.CreateGroupRequest{
				ScopeId: defaultPGroup.GetScopeId(),
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.CreateGroupResponse{
				Uri: fmt.Sprintf("orgs/%s/projects/%s/groups/%s_", defaultOGroup.GetScopeId(), defaultPGroup.GetScopeId(), iam.GroupPrefix),
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateGroupRequest{Item: &pb.Group{
				Id: iam.GroupPrefix + "_notallowed",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateGroupRequest{Item: &pb.Group{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateGroupRequest{Item: &pb.Group{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateGroupRequest)
			proto.Merge(req, tc.req)

			s, err := groups.NewService(repo)
			require.NoError(err, "Error when getting new group service.")

			got, gErr := s.CreateGroup(auth.DisabledAuthContext(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateGroup(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			if got != nil {
				assert.True(strings.HasPrefix(got.GetUri(), tc.res.Uri))
				assert.True(strings.HasPrefix(got.GetItem().GetId(), iam.GroupPrefix+"_"))
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				// Verify it is a group created after the test setup's default group
				assert.True(gotCreateTime.After(defaultCreated), "New group should have been created after default group. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.After(defaultCreated), "New group should have been updated after default group. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.True(proto.Equal(got, tc.res), "CreateGroup(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	require := require.New(t)
	og, pg, repoFn := createDefaultGroupsAndRepo(t)
	tested, err := groups.NewService(repoFn)
	require.NoError(err, "Error when getting new group service.")

	resetGroups := func() {
		repo, err := repoFn()
		require.NoError(err, "Couldn't get a new repo")
		og, _, err = repo.UpdateGroup(context.Background(), og, []string{"Name", "Description"})
		require.NoError(err, "Failed to reset the group")
		pg, _, err = repo.UpdateGroup(context.Background(), pg, []string{"Name", "Description"})
		require.NoError(err, "Failed to reset the group")
	}

	created, err := ptypes.Timestamp(og.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp")
	toMerge := &pbs.UpdateGroupRequest{
		ScopeId: og.GetScopeId(),
		Id:      og.GetPublicId(),
	}

	cases := []struct {
		name    string
		req     *pbs.UpdateGroupRequest
		res     *pbs.UpdateGroupResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing Group",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          og.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          og.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update an Existing Project Scoped Group",
			req: &pbs.UpdateGroupRequest{
				ScopeId: pg.GetScopeId(),
				Id:      pg.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          pg.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: pg.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateGroupRequest{
				ScopeId: pg.GetScopeId(),
				Id:      pg.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          pg.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: pg.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateGroupRequest{
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Group{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          og.GetPublicId(),
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          og.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateGroupResponse{
				Item: &pb.Group{
					Id:          og.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		// TODO: Updating a non existant group should result in a NotFound exception but currently results in
		// the repoFn returning an internal error.
		{
			name: "Update a Non Existing Group",
			req: &pbs.UpdateGroupRequest{
				Id: iam.GroupPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.Internal,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateGroupRequest{
				Id: og.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Group{
					Id:          iam.GroupPrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Group{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateGroupRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Group{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer resetGroups()
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateGroupRequest)
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateGroup(auth.DisabledAuthContext(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateGroup(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateGroup response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a group updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated group should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			assert.True(proto.Equal(got, tc.res), "UpdateGroup(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
