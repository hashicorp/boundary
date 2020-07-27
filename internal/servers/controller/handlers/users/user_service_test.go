package users_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/watchtower/internal/auth"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/users"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/users"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createDefaultUserAndRepo(t *testing.T) (*iam.User, func() (*iam.Repository, error)) {
	t.Helper()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	return u, repoFn
}

func TestGet(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	u, repo := createDefaultUserAndRepo(t)
	toMerge := &pbs.GetUserRequest{
		Id: u.GetPublicId(),
	}

	wantU := &pb.User{
		Id:          u.GetPublicId(),
		Scope:       &scopes.ScopeInfo{Id: u.ScopeId, Type: scope.Org.String()},
		Name:        &wrapperspb.StringValue{Value: u.GetName()},
		Description: &wrapperspb.StringValue{Value: u.GetDescription()},
		CreatedTime: u.CreateTime.GetTimestamp(),
		UpdatedTime: u.UpdateTime.GetTimestamp(),
	}

	cases := []struct {
		name    string
		req     *pbs.GetUserRequest
		res     *pbs.GetUserResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing User",
			req:     &pbs.GetUserRequest{Id: u.GetPublicId()},
			res:     &pbs.GetUserResponse{Item: wantU},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existant User",
			req:     &pbs.GetUserRequest{Id: iam.UserPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetUserRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetUserRequest{Id: iam.UserPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetUserRequest)
			proto.Merge(req, tc.req)

			s, err := users.NewService(repo)
			require.NoError(err, "Couldn't create new user service.")

			got, gErr := s.GetUser(auth.DisabledAuthTestContext(auth.WithScopeId(u.GetScopeId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetUser(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetUser(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}
	repo, err := repoFn()
	require.NoError(err)

	oNoUsers, _ := iam.TestScopes(t, conn)
	oWithUsers, _ := iam.TestScopes(t, conn)

	var wantUsers []*pb.User
	for i := 0; i < 10; i++ {
		newU, err := iam.NewUser(oWithUsers.GetPublicId())
		require.NoError(err)
		u, err := repo.CreateUser(context.Background(), newU)
		require.NoError(err)
		wantUsers = append(wantUsers, &pb.User{
			Id:          u.GetPublicId(),
			Scope:       &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String()},
			CreatedTime: u.GetCreateTime().GetTimestamp(),
			UpdatedTime: u.GetUpdateTime().GetTimestamp(),
		})
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.ListUsersRequest
		res     *pbs.ListUsersResponse
		errCode codes.Code
	}{
		{
			name:    "List Many Users",
			scopeId: oWithUsers.GetPublicId(),
			req:     &pbs.ListUsersRequest{},
			res:     &pbs.ListUsersResponse{Items: wantUsers},
			errCode: codes.OK,
		},
		{
			name:    "List No Users",
			scopeId: oNoUsers.GetPublicId(),
			req:     &pbs.ListUsersRequest{},
			res:     &pbs.ListUsersResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := users.NewService(repoFn)
			require.NoError(err, "Couldn't create new user service.")

			got, gErr := s.ListUsers(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "ListUsers(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "ListUsers(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	require := require.New(t)
	u, repo := createDefaultUserAndRepo(t)

	s, err := users.NewService(repo)
	require.NoError(err, "Error when getting new user service.")

	cases := []struct {
		name    string
		req     *pbs.DeleteUserRequest
		res     *pbs.DeleteUserResponse
		errCode codes.Code
	}{
		{
			name: "Delete an Existing User",
			req: &pbs.DeleteUserRequest{
				Id: u.GetPublicId(),
			},
			res: &pbs.DeleteUserResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad user id",
			req: &pbs.DeleteUserRequest{
				Id: iam.UserPrefix + "_doesntexis",
			},
			res: &pbs.DeleteUserResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad User Id formatting",
			req: &pbs.DeleteUserRequest{
				Id: "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteUser(auth.DisabledAuthTestContext(auth.WithScopeId(u.GetScopeId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteUser(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteUser(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	u, repo := createDefaultUserAndRepo(t)

	s, err := users.NewService(repo)
	require.NoError(err, "Error when getting new user service")
	req := &pbs.DeleteUserRequest{
		Id: u.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(auth.WithScopeId(u.GetScopeId()))
	got, gErr := s.DeleteUser(ctx, req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteUser(ctx, req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	require := require.New(t)
	defaultUser, repo := createDefaultUserAndRepo(t)
	defaultCreated, err := ptypes.Timestamp(defaultUser.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp.")
	toMerge := &pbs.CreateUserRequest{}

	cases := []struct {
		name    string
		req     *pbs.CreateUserRequest
		res     *pbs.CreateUserResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid User",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateUserResponse{
				Uri: fmt.Sprintf("scopes/%s/users/u_", defaultUser.GetScopeId()),
				Item: &pb.User{
					Scope:       &scopes.ScopeInfo{Id: defaultUser.GetScopeId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				Id: iam.UserPrefix + "_notallowed",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateUserRequest)
			proto.Merge(req, tc.req)

			s, err := users.NewService(repo)
			require.NoError(err, "Error when getting new user service.")

			got, gErr := s.CreateUser(auth.DisabledAuthTestContext(auth.WithScopeId(defaultUser.GetScopeId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateUser(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			if got != nil {
				assert.True(strings.HasPrefix(got.GetUri(), tc.res.Uri))
				assert.True(strings.HasPrefix(got.GetItem().GetId(), iam.UserPrefix+"_"))
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				// Verify it is a user created after the test setup's default user
				assert.True(gotCreateTime.After(defaultCreated), "New user should have been created after default user. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.After(defaultCreated), "New user should have been updated after default user. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.True(proto.Equal(got, tc.res), "CreateUser(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	require := require.New(t)
	u, repoFn := createDefaultUserAndRepo(t)
	tested, err := users.NewService(repoFn)
	require.NoError(err, "Error when getting new user service.")

	resetUser := func() {
		repo, err := repoFn()
		require.NoError(err, "Couldn't get a new repo")
		u, _, err = repo.UpdateUser(context.Background(), u, []string{"Name", "Description"})
		require.NoError(err, "Failed to reset the user")
	}

	created, err := ptypes.Timestamp(u.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp")
	toMerge := &pbs.UpdateUserRequest{
		Id: u.GetPublicId(),
	}

	cases := []struct {
		name    string
		req     *pbs.UpdateUserRequest
		res     *pbs.UpdateUserResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing User",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateUserResponse{
				Item: &pb.User{
					Id:          u.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: u.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateUserResponse{
				Item: &pb.User{
					Id:          u.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: u.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateUserRequest{
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.User{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateUserResponse{
				Item: &pb.User{
					Id:          u.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String()},
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: u.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateUserResponse{
				Item: &pb.User{
					Id:          u.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: u.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateUserResponse{
				Item: &pb.User{
					Id:          u.GetPublicId(),
					Scope:       &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String()},
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime: u.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		// TODO: Updating a non existant user should result in a NotFound exception but currently results in
		// the repoFn returning an internal error.
		{
			name: "Update a Non Existing User",
			req: &pbs.UpdateUserRequest{
				Id: iam.UserPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.Internal,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateUserRequest{
				Id: u.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.User{
					Id:          iam.UserPrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.User{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateUserRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.User{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer resetUser()
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateUserRequest)
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateUser(auth.DisabledAuthTestContext(auth.WithScopeId(u.GetScopeId())), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateUser(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateUser response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a user updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated user should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			assert.True(proto.Equal(got, tc.res), "UpdateUser(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
