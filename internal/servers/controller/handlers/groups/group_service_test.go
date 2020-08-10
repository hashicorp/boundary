package groups_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/watchtower/internal/auth"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/groups"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/groups"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
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

func equalMembers(g *pb.Group, members []string) bool {
	if len(g.Members) != len(members) {
		return false
	}
	for _, m := range members {
		var foundInMembers bool
		var foundInPrincipalIds bool
		for _, v := range g.Members {
			if v.Id == m {
				foundInMembers = true
			}
		}
		for _, v := range g.MemberIds {
			if v == m {
				foundInPrincipalIds = true
			}
		}
		if !foundInMembers || !foundInPrincipalIds {
			return false
		}
	}
	return true
}

func TestGet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}

	o, p := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, o.GetPublicId())

	og := iam.TestGroup(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestGroupMember(t, conn, og.GetPublicId(), u.GetPublicId())

	pg := iam.TestGroup(t, conn, p.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestGroupMember(t, conn, pg.GetPublicId(), u.GetPublicId())

	toMerge := &pbs.GetGroupRequest{
		Id: og.GetPublicId(),
	}

	wantOrgGroup := &pb.Group{
		Id:          og.GetPublicId(),
		Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String()},
		Name:        &wrapperspb.StringValue{Value: og.GetName()},
		Description: &wrapperspb.StringValue{Value: og.GetDescription()},
		CreatedTime: og.CreateTime.GetTimestamp(),
		UpdatedTime: og.UpdateTime.GetTimestamp(),
		Version:     1,
		MemberIds:   []string{u.GetPublicId()},
		Members: []*pb.Member{
			{
				Id:      u.GetPublicId(),
				Type:    iam.UserMemberType.String(),
				ScopeId: u.GetScopeId(),
			},
		},
	}

	wantProjGroup := &pb.Group{
		Id:          pg.GetPublicId(),
		Scope:       &scopes.ScopeInfo{Id: pg.GetScopeId(), Type: scope.Project.String()},
		Name:        &wrapperspb.StringValue{Value: pg.GetName()},
		Description: &wrapperspb.StringValue{Value: pg.GetDescription()},
		CreatedTime: pg.CreateTime.GetTimestamp(),
		UpdatedTime: pg.UpdateTime.GetTimestamp(),
		Version:     1,
		MemberIds:   []string{u.GetPublicId()},
		Members: []*pb.Member{
			{
				Id:      u.GetPublicId(),
				Type:    iam.UserMemberType.String(),
				ScopeId: u.GetScopeId(),
			},
		},
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetGroupRequest
		res     *pbs.GetGroupResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing Group",
			scopeId: og.GetScopeId(),
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
			scopeId: pg.GetScopeId(),
			req:     &pbs.GetGroupRequest{Id: pg.GetPublicId()},
			res:     &pbs.GetGroupResponse{Item: wantProjGroup},
			errCode: codes.OK,
		},
		{
			name:    "Project Scoped Get a non existant Group",
			scopeId: pg.GetScopeId(),
			req:     &pbs.GetGroupRequest{Id: iam.GroupPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Project Scoped Wrong id prefix",
			scopeId: pg.GetScopeId(),
			req:     &pbs.GetGroupRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Project Scoped space in id",
			scopeId: pg.GetScopeId(),
			req:     &pbs.GetGroupRequest{Id: iam.GroupPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetGroupRequest)
			proto.Merge(req, tc.req)

			s, err := groups.NewService(repoFn)
			require.NoError(err, "Couldn't create new group service.")

			got, gErr := s.GetGroup(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetGroup(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetGroup(%q) got response\n%q, wanted\n%q", req, got, tc.res)
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
			Scope:       &scopes.ScopeInfo{Id: oWithGroups.GetPublicId(), Type: scope.Org.String()},
			CreatedTime: og.GetCreateTime().GetTimestamp(),
			UpdatedTime: og.GetUpdateTime().GetTimestamp(),
			Version:     1,
		})
		pg := iam.TestGroup(t, conn, pWithGroups.GetPublicId())
		wantProjGroups = append(wantProjGroups, &pb.Group{
			Id:          pg.GetPublicId(),
			Scope:       &scopes.ScopeInfo{Id: pWithGroups.GetPublicId(), Type: scope.Project.String()},
			CreatedTime: pg.GetCreateTime().GetTimestamp(),
			UpdatedTime: pg.GetUpdateTime().GetTimestamp(),
			Version:     1,
		})
	}

	cases := []struct {
		name    string
		scopeId string
		res     *pbs.ListGroupsResponse
		errCode codes.Code
	}{
		{
			name:    "List Many Group",
			scopeId: oWithGroups.GetPublicId(),
			res:     &pbs.ListGroupsResponse{Items: wantOrgGroups},
			errCode: codes.OK,
		},
		{
			name:    "List No Groups",
			scopeId: oNoGroups.GetPublicId(),
			res:     &pbs.ListGroupsResponse{},
			errCode: codes.OK,
		},
		{
			name:    "List Many Project Group",
			scopeId: pWithGroups.GetPublicId(),
			res:     &pbs.ListGroupsResponse{Items: wantProjGroups},
			errCode: codes.OK,
		},
		{
			name:    "List No Project Groups",
			scopeId: pNoGroups.GetPublicId(),
			res:     &pbs.ListGroupsResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := groups.NewService(repoFn)
			require.NoError(err, "Couldn't create new group service.")

			got, gErr := s.ListGroups(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), &pbs.ListGroupsRequest{})
			assert.Equal(tc.errCode, status.Code(gErr), "ListGroups(%q) got error %v, wanted %v", tc.scopeId, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListGroups(%q) got response %q, wanted %q", tc.scopeId, got, tc.res)
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
		scopeId string
		req     *pbs.DeleteGroupRequest
		res     *pbs.DeleteGroupResponse
		errCode codes.Code
	}{
		{
			name:    "Delete an Existing Group",
			scopeId: og.GetScopeId(),
			req: &pbs.DeleteGroupRequest{
				Id: og.GetPublicId(),
			},
			res: &pbs.DeleteGroupResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name:    "Delete bad group id",
			scopeId: og.GetScopeId(),
			req: &pbs.DeleteGroupRequest{
				Id: iam.GroupPrefix + "_doesntexis",
			},
			res: &pbs.DeleteGroupResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name:    "Delete bad org id",
			scopeId: "o_doesntexist",
			req: &pbs.DeleteGroupRequest{
				Id: og.GetPublicId(),
			},
			res: &pbs.DeleteGroupResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name:    "Bad Group Id formatting",
			scopeId: og.GetScopeId(),
			req: &pbs.DeleteGroupRequest{
				Id: "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Project Scoped Delete an Existing Group",
			scopeId: pg.GetScopeId(),
			req: &pbs.DeleteGroupRequest{
				Id: pg.GetPublicId(),
			},
			res: &pbs.DeleteGroupResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name:    "Project Scoped Delete bad group id",
			scopeId: pg.GetScopeId(),
			req: &pbs.DeleteGroupRequest{
				Id: iam.GroupPrefix + "_doesntexis",
			},
			res: &pbs.DeleteGroupResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name:    "Project Scoped Delete bad project id",
			scopeId: "p_doesntexis",
			req: &pbs.DeleteGroupRequest{
				Id: pg.GetPublicId(),
			},
			res: &pbs.DeleteGroupResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteGroup(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteGroup(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteGroup(%+v) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	og, pg, repo := createDefaultGroupsAndRepo(t)

	s, err := groups.NewService(repo)
	require.NoError(err, "Error when getting new group service")
	scopeId := og.GetScopeId()
	req := &pbs.DeleteGroupRequest{
		Id: og.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(auth.WithScopeId(scopeId))
	got, gErr := s.DeleteGroup(ctx, req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteGroup(ctx, req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")

	scopeId = pg.GetScopeId()
	projReq := &pbs.DeleteGroupRequest{
		Id: pg.GetPublicId(),
	}
	ctx = auth.DisabledAuthTestContext(auth.WithScopeId(scopeId))
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
	toMerge := &pbs.CreateGroupRequest{}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.CreateGroupRequest
		res     *pbs.CreateGroupResponse
		errCode codes.Code
	}{
		{
			name:    "Create a valid Group",
			scopeId: defaultOGroup.GetScopeId(),
			req: &pbs.CreateGroupRequest{Item: &pb.Group{
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateGroupResponse{
				Uri: fmt.Sprintf("scopes/%s/groups/%s_", defaultOGroup.GetScopeId(), iam.GroupPrefix),
				Item: &pb.Group{
					Scope:       &scopes.ScopeInfo{Id: defaultOGroup.GetScopeId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Version:     1,
				},
			},
			errCode: codes.OK,
		},
		{
			name:    "Create a valid Project Scoped Group",
			scopeId: defaultPGroup.GetScopeId(),
			req: &pbs.CreateGroupRequest{
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.CreateGroupResponse{
				Uri: fmt.Sprintf("scopes/%s/groups/%s_", defaultPGroup.GetScopeId(), iam.GroupPrefix),
				Item: &pb.Group{
					Scope:       &scopes.ScopeInfo{Id: defaultPGroup.GetScopeId(), Type: scope.Project.String()},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Version:     1,
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

			got, gErr := s.CreateGroup(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateGroup(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
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
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateGroup(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}

	o, p := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, o.GetPublicId())

	og := iam.TestGroup(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestGroupMember(t, conn, og.GetPublicId(), u.GetPublicId())

	pg := iam.TestGroup(t, conn, p.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestGroupMember(t, conn, pg.GetPublicId(), u.GetPublicId())

	var ogVersion uint32 = 1
	var pgVersion uint32 = 1

	resetGroups := func(proj bool) {
		repo, err := repoFn()
		require.NoError(err, "Couldn't get a new repo")
		if proj {
			pgVersion++
			pg, _, _, err = repo.UpdateGroup(context.Background(), pg, pgVersion, []string{"Name", "Description"})
			require.NoError(err, "Failed to reset the group")
			pgVersion++
		} else {
			ogVersion++
			og, _, _, err = repo.UpdateGroup(context.Background(), og, ogVersion, []string{"Name", "Description"})
			require.NoError(err, "Failed to reset the group")
			ogVersion++
		}
	}

	created, err := ptypes.Timestamp(og.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp")
	toMerge := &pbs.UpdateGroupRequest{
		Id: og.GetPublicId(),
	}

	tested, err := groups.NewService(repoFn)
	cases := []struct {
		name    string
		scopeId string
		req     *pbs.UpdateGroupRequest
		res     *pbs.UpdateGroupResponse
		errCode codes.Code
	}{
		{
			name:    "Update an Existing Group",
			scopeId: og.GetScopeId(),
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
					Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							Type:    iam.UserMemberType.String(),
							ScopeId: u.GetScopeId(),
						},
					},
				},
			},
			errCode: codes.OK,
		},
		{
			name:    "Multiple Paths in single string",
			scopeId: og.GetScopeId(),
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
					Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							Type:    iam.UserMemberType.String(),
							ScopeId: u.GetScopeId(),
						},
					},
				},
			},
			errCode: codes.OK,
		},
		{
			name:    "Update an Existing Project Scoped Group",
			scopeId: pg.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				Id: pg.GetPublicId(),
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
					Scope:       &scopes.ScopeInfo{Id: pg.GetScopeId(), Type: scope.Project.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: pg.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							Type:    iam.UserMemberType.String(),
							ScopeId: u.GetScopeId(),
						},
					},
				},
			},
			errCode: codes.OK,
		},
		{
			name:    "Multiple Paths in single string",
			scopeId: pg.GetScopeId(),
			req: &pbs.UpdateGroupRequest{
				Id: pg.GetPublicId(),
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
					Scope:       &scopes.ScopeInfo{Id: pg.GetScopeId(), Type: scope.Project.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: pg.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							Type:    iam.UserMemberType.String(),
							ScopeId: u.GetScopeId(),
						},
					},
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
			name:    "No Paths in Mask",
			scopeId: og.GetScopeId(),
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
			name:    "Only non-existant paths in Mask",
			scopeId: og.GetScopeId(),
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
			name:    "Unset Name",
			scopeId: og.GetScopeId(),
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
					Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String()},
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							Type:    iam.UserMemberType.String(),
							ScopeId: u.GetScopeId(),
						},
					},
				},
			},
			errCode: codes.OK,
		},
		{
			name:    "Update Only Name",
			scopeId: og.GetScopeId(),
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
					Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							Type:    iam.UserMemberType.String(),
							ScopeId: u.GetScopeId(),
						},
					},
				},
			},
			errCode: codes.OK,
		},
		{
			name:    "Update Only Description",
			scopeId: og.GetScopeId(),
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
					Scope:       &scopes.ScopeInfo{Id: og.GetScopeId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime: og.GetCreateTime().GetTimestamp(),
					MemberIds:   []string{u.GetPublicId()},
					Members: []*pb.Member{
						{
							Id:      u.GetPublicId(),
							Type:    iam.UserMemberType.String(),
							ScopeId: u.GetScopeId(),
						},
					},
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
			ver := ogVersion
			if tc.req.Id == pg.PublicId {
				ver = pgVersion
			}
			tc.req.Version = ver

			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateGroupRequest)
			proto.Merge(req, tc.req)

			// Test with bad version (too high, too low)
			req.Version = ver + 2
			_, gErr := tested.UpdateGroup(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			require.Error(gErr)
			req.Version = ver - 1
			_, gErr = tested.UpdateGroup(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			require.Error(gErr)
			req.Version = ver

			got, gErr := tested.UpdateGroup(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateGroup(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if tc.errCode == codes.OK {
				defer resetGroups(req.Id == pg.PublicId)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateGroup response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a group updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated group should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

				assert.Equal(ver+1, got.GetItem().GetVersion())
				tc.res.Item.Version = ver + 1
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateGroup(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestAddMember(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}
	s, err := groups.NewService(repoFn)
	require.NoError(t, err, "Error when getting new group service.")

	o, p := iam.TestScopes(t, conn)
	users := []*iam.User{
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
	}

	addCases := []struct {
		name         string
		setup        func(*iam.Group)
		addUsers     []string
		addGroups    []string
		resultUsers  []string
		resultGroups []string
		wantErr      bool
	}{
		{
			name:        "Add user on empty group",
			setup:       func(g *iam.Group) {},
			addUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Add user on populated group",
			setup: func(g *iam.Group) {
				iam.TestGroupMember(t, conn, g.GetPublicId(), users[0].GetPublicId())
			},
			addUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[0].GetPublicId(), users[1].GetPublicId()},
		},
		{
			name: "Add empty on populated group",
			setup: func(g *iam.Group) {
				iam.TestGroupMember(t, conn, g.GetPublicId(), users[0].GetPublicId())
				iam.TestGroupMember(t, conn, g.GetPublicId(), users[1].GetPublicId())
			},
			wantErr: true,
		},
	}

	for _, tc := range addCases {
		for _, scp := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scp.GetType(), func(t *testing.T) {
				grp := iam.TestGroup(t, conn, scp.GetPublicId())
				tc.setup(grp)
				req := &pbs.AddGroupMembersRequest{
					Id:      grp.GetPublicId(),
					Version: grp.GetVersion(),
					Item: &pbs.GroupMemberIdsMessage{
						MemberIds: tc.addUsers,
					},
				}

				got, err := s.AddGroupMembers(auth.DisabledAuthTestContext(auth.WithScopeId(scp.GetPublicId())), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalMembers(got.GetItem(), tc.resultUsers))
			})
		}
	}

	grp := iam.TestGroup(t, conn, p.GetPublicId())

	failCases := []struct {
		name    string
		req     *pbs.AddGroupMembersRequest
		errCode codes.Code
	}{
		{
			name: "Bad Group Id",
			req: &pbs.AddGroupMembersRequest{
				Id:      "bad id",
				Version: grp.GetVersion(),
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.AddGroupMembers(auth.DisabledAuthTestContext(auth.WithScopeId(grp.GetScopeId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "AddGroupMembers(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}

func TestSetMember(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}
	s, err := groups.NewService(repoFn)
	require.NoError(t, err, "Error when getting new group service.")

	o, p := iam.TestScopes(t, conn)
	users := []*iam.User{
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
	}

	setCases := []struct {
		name         string
		setup        func(*iam.Group)
		setUsers     []string
		setGroups    []string
		resultUsers  []string
		resultGroups []string
		wantErr      bool
	}{
		{
			name:        "Set user on empty group",
			setup:       func(r *iam.Group) {},
			setUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Set user on populated group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
			},
			setUsers:    []string{users[1].GetPublicId()},
			resultUsers: []string{users[1].GetPublicId()},
		},
		{
			name: "Set empty on populated group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			setUsers:    []string{},
			resultUsers: nil,
		},
	}

	for _, tc := range setCases {
		for _, scp := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scp.GetType(), func(t *testing.T) {
				grp := iam.TestGroup(t, conn, scp.GetPublicId())
				tc.setup(grp)
				req := &pbs.SetGroupMembersRequest{
					Id:      grp.GetPublicId(),
					Version: grp.GetVersion(),
					Item: &pbs.GroupMemberIdsMessage{
						MemberIds: tc.setUsers,
					},
				}

				got, err := s.SetGroupMembers(auth.DisabledAuthTestContext(auth.WithScopeId(scp.GetPublicId())), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalMembers(got.GetItem(), append(tc.resultUsers, tc.resultGroups...)))
			})
		}
	}

	grp := iam.TestGroup(t, conn, p.GetPublicId())

	failCases := []struct {
		name    string
		req     *pbs.SetGroupMembersRequest
		errCode codes.Code
	}{
		{
			name: "Bad Group Id",
			req: &pbs.SetGroupMembersRequest{
				Id:      "bad id",
				Version: grp.GetVersion(),
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.SetGroupMembers(auth.DisabledAuthTestContext(auth.WithScopeId(grp.GetScopeId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "SetGroupMembers(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}

func TestRemoveMember(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}
	s, err := groups.NewService(repoFn)
	require.NoError(t, err, "Error when getting new grp service.")

	o, p := iam.TestScopes(t, conn)
	users := []*iam.User{
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
		iam.TestUser(t, conn, o.GetPublicId()),
	}

	addCases := []struct {
		name         string
		setup        func(*iam.Group)
		removeUsers  []string
		removeGroups []string
		resultUsers  []string
		resultGroups []string
		wantErr      bool
	}{
		{
			name:        "Remove user on empty group",
			setup:       func(r *iam.Group) {},
			removeUsers: []string{users[1].GetPublicId()},
			wantErr:     true,
		},
		{
			name: "Remove 1 of 2 users from group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			removeUsers: []string{users[1].GetPublicId()},
			resultUsers: []string{users[0].GetPublicId()},
		},
		{
			name: "Remove all users from group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[1].GetPublicId())
			},
			removeUsers: []string{users[0].GetPublicId(), users[1].GetPublicId()},
			resultUsers: []string{},
		},
		{
			name: "Remove empty on populated group",
			setup: func(r *iam.Group) {
				iam.TestGroupMember(t, conn, r.GetPublicId(), users[0].GetPublicId())
			},
			wantErr: true,
		},
	}

	for _, tc := range addCases {
		for _, scp := range []*iam.Scope{o, p} {
			t.Run(tc.name+"_"+scp.GetType(), func(t *testing.T) {
				grp := iam.TestGroup(t, conn, scp.GetPublicId())
				tc.setup(grp)
				req := &pbs.RemoveGroupMembersRequest{
					Id:      grp.GetPublicId(),
					Version: grp.GetVersion(),
					Item: &pbs.GroupMemberIdsMessage{
						MemberIds: tc.removeUsers,
					},
				}

				got, err := s.RemoveGroupMembers(auth.DisabledAuthTestContext(auth.WithScopeId(scp.GetPublicId())), req)
				if tc.wantErr {
					assert.Error(t, err)
					return
				}
				s, ok := status.FromError(err)
				require.True(t, ok)
				require.NoError(t, err, "Got error: %v", s)

				assert.True(t, equalMembers(got.GetItem(), tc.resultUsers))
			})
		}
	}

	grp := iam.TestGroup(t, conn, p.GetPublicId())

	failCases := []struct {
		name    string
		req     *pbs.AddGroupMembersRequest
		errCode codes.Code
	}{
		{
			name: "Bad Group Id",
			req: &pbs.AddGroupMembersRequest{
				Id:      "bad id",
				Version: grp.GetVersion(),
			},
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			_, gErr := s.AddGroupMembers(auth.DisabledAuthTestContext(auth.WithScopeId(grp.GetScopeId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "AddGroupMembers(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
		})
	}
}
