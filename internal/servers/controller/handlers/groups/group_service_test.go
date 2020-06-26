package groups_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
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

func createDefaultGroupAndRepo(t *testing.T) (*iam.Group, func() (*iam.Repository, error)) {
	t.Helper()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Error when closing gorm DB: %v", err)
		}
		if err := cleanup(); err != nil {
			t.Errorf("Error when cleaning up TestSetup: %v", err)
		}
	})
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	g := iam.TestGroup(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	return g, repoFn
}

func TestGet(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	g, repo := createDefaultGroupAndRepo(t)
	toMerge := &pbs.GetGroupRequest{
		OrgId: g.GetScopeId(),
		Id:    g.GetPublicId(),
	}

	wantU := &pb.Group{
		Id:          g.GetPublicId(),
		Name:        &wrapperspb.StringValue{Value: g.GetName()},
		Description: &wrapperspb.StringValue{Value: g.GetDescription()},
		CreatedTime: g.CreateTime.GetTimestamp(),
		UpdatedTime: g.UpdateTime.GetTimestamp(),
	}

	cases := []struct {
		name    string
		req     *pbs.GetGroupRequest
		res     *pbs.GetGroupResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing Group",
			req:     &pbs.GetGroupRequest{Id: g.GetPublicId()},
			res:     &pbs.GetGroupResponse{Item: wantU},
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetGroupRequest)
			proto.Merge(req, tc.req)

			s, err := groups.NewService(repo)
			require.NoError(err, "Couldn't create new group service.")

			got, gErr := s.GetGroup(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetGroup(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetGroup(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Error when closing gorm DB: %v", err)
		}
		if err := cleanup(); err != nil {
			t.Errorf("Error when cleaning up TestSetup: %v", err)
		}
	})
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}
	oNoGroups, _ := iam.TestScopes(t, conn)
	oWithGroups, _ := iam.TestScopes(t, conn)
	var wantGroups []*pb.Group
	for i := 0; i < 10; i++ {
		g := iam.TestGroup(t, conn, oWithGroups.GetPublicId())
		wantGroups = append(wantGroups, &pb.Group{
			Id:          g.GetPublicId(),
			CreatedTime: g.GetCreateTime().GetTimestamp(),
			UpdatedTime: g.GetUpdateTime().GetTimestamp(),
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
			req:     &pbs.ListGroupsRequest{OrgId: oWithGroups.GetPublicId()},
			res:     &pbs.ListGroupsResponse{Items: wantGroups},
			errCode: codes.OK,
		},
		{
			name:    "List No Groups",
			req:     &pbs.ListGroupsRequest{OrgId: oNoGroups.GetPublicId()},
			res:     &pbs.ListGroupsResponse{},
			errCode: codes.OK,
		},
		{
			name:    "Invalid Org Id",
			req:     &pbs.ListGroupsRequest{OrgId: scope.Organization.Prefix() + "_this is invalid"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		// TODO: When an org doesn't exist, we should return a 404 instead of an empty list.
		{
			name:    "Unfound Org",
			req:     &pbs.ListGroupsRequest{OrgId: scope.Organization.Prefix() + "_DoesntExis"},
			res:     &pbs.ListGroupsResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := groups.NewService(repoFn)
			require.NoError(err, "Couldn't create new group service.")

			got, gErr := s.ListGroups(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "ListGroups(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "ListGroups(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	require := require.New(t)
	g, repo := createDefaultGroupAndRepo(t)

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
				OrgId: g.GetScopeId(),
				Id:    g.GetPublicId(),
			},
			res: &pbs.DeleteGroupResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad group id",
			req: &pbs.DeleteGroupRequest{
				OrgId: g.GetScopeId(),
				Id:    iam.GroupPrefix + "_doesntexis",
			},
			res: &pbs.DeleteGroupResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad org id",
			req: &pbs.DeleteGroupRequest{
				OrgId: "o_doesntexis",
				Id:    g.GetPublicId(),
			},
			res: &pbs.DeleteGroupResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad org formatting",
			req: &pbs.DeleteGroupRequest{
				OrgId: "bad_format",
				Id:    g.GetPublicId(),
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Group Id formatting",
			req: &pbs.DeleteGroupRequest{
				OrgId: g.GetScopeId(),
				Id:    "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteGroup(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteGroup(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	g, repo := createDefaultGroupAndRepo(t)

	s, err := groups.NewService(repo)
	require.NoError(err, "Error when getting new group service")
	req := &pbs.DeleteGroupRequest{
		OrgId: g.GetScopeId(),
		Id:    g.GetPublicId(),
	}
	got, gErr := s.DeleteGroup(context.Background(), req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteGroup(context.Background(), req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	require := require.New(t)
	defaultGroup, repo := createDefaultGroupAndRepo(t)
	defaultCreated, err := ptypes.Timestamp(defaultGroup.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp.")
	toMerge := &pbs.CreateGroupRequest{
		OrgId: defaultGroup.GetScopeId(),
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
				Uri: fmt.Sprintf("orgs/%s/groups/%s_", defaultGroup.GetScopeId(), iam.GroupPrefix),
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

			got, gErr := s.CreateGroup(context.Background(), req)
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
	g, repoFn := createDefaultGroupAndRepo(t)
	tested, err := groups.NewService(repoFn)
	require.NoError(err, "Error when getting new group service.")

	resetGroup := func() {
		repo, err := repoFn()
		require.NoError(err, "Couldn't get a new repo")
		g, _, err = repo.UpdateGroup(context.Background(), g, []string{"Name", "Description"})
		require.NoError(err, "Failed to reset the group")
	}

	created, err := ptypes.Timestamp(g.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp")
	toMerge := &pbs.UpdateGroupRequest{
		OrgId: g.GetScopeId(),
		Id:    g.GetPublicId(),
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
					Id:          g.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: g.GetCreateTime().GetTimestamp(),
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
					Id:          g.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: g.GetCreateTime().GetTimestamp(),
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
					Id:          g.GetPublicId(),
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: g.GetCreateTime().GetTimestamp(),
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
					Id:          g.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: g.GetCreateTime().GetTimestamp(),
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
					Id:          g.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime: g.GetCreateTime().GetTimestamp(),
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
				Id: g.GetPublicId(),
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
			defer resetGroup()
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateGroupRequest)
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateGroup(context.Background(), req)
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
