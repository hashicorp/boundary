package users_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/users"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/users"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createDefaultUserAndRepo(t *testing.T) (*iam.User, func() (*iam.Repository, error)) {
	t.Helper()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return repo, nil
	}
	o, _ := iam.TestScopes(t, repo)
	u := iam.TestUser(t, repo, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	return u, repoFn
}

func TestGet(t *testing.T) {
	u, repoFn := createDefaultUserAndRepo(t)
	toMerge := &pbs.GetUserRequest{
		Id: u.GetPublicId(),
	}

	wantU := &pb.User{
		Id:                u.GetPublicId(),
		ScopeId:           u.GetScopeId(),
		Scope:             &scopes.ScopeInfo{Id: u.ScopeId, Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Name:              &wrapperspb.StringValue{Value: u.GetName()},
		Description:       &wrapperspb.StringValue{Value: u.GetDescription()},
		CreatedTime:       u.CreateTime.GetTimestamp(),
		UpdatedTime:       u.UpdateTime.GetTimestamp(),
		Version:           1,
		AuthorizedActions: []string{"read", "update", "delete", "add-accounts", "set-accounts", "remove-accounts"},
	}

	cases := []struct {
		name string
		req  *pbs.GetUserRequest
		res  *pbs.GetUserResponse
		err  error
	}{
		{
			name: "Get an Existing User",
			req:  &pbs.GetUserRequest{Id: u.GetPublicId()},
			res:  &pbs.GetUserResponse{Item: wantU},
		},
		{
			name: "Get a non existant User",
			req:  &pbs.GetUserRequest{Id: iam.UserPrefix + "_DoesntExis"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetUserRequest{Id: "j_1234567890"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "space in id",
			req:  &pbs.GetUserRequest{Id: iam.UserPrefix + "_1 23456789"},
			res:  nil,
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.GetUserRequest)
			proto.Merge(req, tc.req)

			s, err := users.NewService(repoFn)
			require.NoError(err, "Couldn't create new user service.")

			got, gErr := s.GetUser(auth.DisabledAuthTestContext(repoFn, u.GetScopeId()), req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetUser(%+v) got error %v, wanted %v", req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetUser(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repo, err := repoFn()
	require.NoError(t, err)

	oNoUsers, _ := iam.TestScopes(t, repo)
	oWithUsers, _ := iam.TestScopes(t, repo)

	s, err := users.NewService(repoFn)

	var wantUsers []*pb.User

	// Populate expected values for recursive test
	var totalUsers []*pb.User
	ctx := auth.DisabledAuthTestContext(repoFn, "global")
	anon, err := s.GetUser(ctx, &pbs.GetUserRequest{Id: "u_anon"})
	require.NoError(t, err)
	totalUsers = append(totalUsers, anon.GetItem())
	authUser, err := s.GetUser(ctx, &pbs.GetUserRequest{Id: "u_auth"})
	require.NoError(t, err)
	totalUsers = append(totalUsers, authUser.GetItem())
	recovery, err := s.GetUser(ctx, &pbs.GetUserRequest{Id: "u_recovery"})
	require.NoError(t, err)
	totalUsers = append(totalUsers, recovery.GetItem())

	// Add new users
	for i := 0; i < 10; i++ {
		newU, err := iam.NewUser(oWithUsers.GetPublicId())
		require.NoError(t, err)
		u, err := repo.CreateUser(context.Background(), newU)
		require.NoError(t, err)
		wantUsers = append(wantUsers, &pb.User{
			Id:                u.GetPublicId(),
			ScopeId:           u.GetScopeId(),
			Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			CreatedTime:       u.GetCreateTime().GetTimestamp(),
			UpdatedTime:       u.GetUpdateTime().GetTimestamp(),
			Version:           1,
			AuthorizedActions: []string{"read", "update", "delete", "add-accounts", "set-accounts", "remove-accounts"},
		})
	}

	// Populate these users into the total
	ctx = auth.DisabledAuthTestContext(repoFn, oWithUsers.GetPublicId())
	usersInOrg, err := s.ListUsers(ctx, &pbs.ListUsersRequest{ScopeId: oWithUsers.GetPublicId()})
	require.NoError(t, err)
	totalUsers = append(totalUsers, usersInOrg.GetItems()...)
	cases := []struct {
		name string
		req  *pbs.ListUsersRequest
		res  *pbs.ListUsersResponse
		err  error
	}{
		{
			name: "List Many Users",
			req:  &pbs.ListUsersRequest{ScopeId: oWithUsers.GetPublicId()},
			res:  &pbs.ListUsersResponse{Items: wantUsers},
		},
		{
			name: "List No Users",
			req:  &pbs.ListUsersRequest{ScopeId: oNoUsers.GetPublicId()},
			res:  &pbs.ListUsersResponse{},
		},
		{
			name: "List Recursively in Org",
			req:  &pbs.ListUsersRequest{ScopeId: oWithUsers.GetPublicId(), Recursive: true},
			res:  &pbs.ListUsersResponse{Items: wantUsers},
		},
		{
			name: "List Recursively in Global",
			req:  &pbs.ListUsersRequest{ScopeId: "global", Recursive: true},
			res:  &pbs.ListUsersResponse{Items: totalUsers},
		},
		{
			name: "Filter Many Users",
			req:  &pbs.ListUsersRequest{ScopeId: "global", Recursive: true, Filter: fmt.Sprintf(`"/item/scope/id"==%q`, oWithUsers.GetPublicId())},
			res:  &pbs.ListUsersResponse{Items: wantUsers},
		},
		{
			name: "Filter To No Users",
			req:  &pbs.ListUsersRequest{ScopeId: oWithUsers.GetPublicId(), Filter: `"/item/id"=="doesntmatch"`},
			res:  &pbs.ListUsersResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListUsersRequest{ScopeId: oWithUsers.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(err, "Couldn't create new user service.")

			got, gErr := s.ListUsers(auth.DisabledAuthTestContext(repoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListUsers(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListUsers(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	u, repoFn := createDefaultUserAndRepo(t)

	s, err := users.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service.")

	cases := []struct {
		name string
		req  *pbs.DeleteUserRequest
		res  *pbs.DeleteUserResponse
		err  error
	}{
		{
			name: "Delete an Existing User",
			req: &pbs.DeleteUserRequest{
				Id: u.GetPublicId(),
			},
		},
		{
			name: "Delete bad user id",
			req: &pbs.DeleteUserRequest{
				Id: iam.UserPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Bad User Id formatting",
			req: &pbs.DeleteUserRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteUser(auth.DisabledAuthTestContext(repoFn, u.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteUser(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteUser(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	u, repoFn := createDefaultUserAndRepo(t)

	s, err := users.NewService(repoFn)
	require.NoError(err, "Error when getting new user service")
	req := &pbs.DeleteUserRequest{
		Id: u.GetPublicId(),
	}
	ctx := auth.DisabledAuthTestContext(repoFn, u.GetScopeId())
	_, gErr := s.DeleteUser(ctx, req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteUser(ctx, req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	defaultUser, repoFn := createDefaultUserAndRepo(t)
	defaultCreated, err := ptypes.Timestamp(defaultUser.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp.")

	cases := []struct {
		name string
		req  *pbs.CreateUserRequest
		res  *pbs.CreateUserResponse
		err  error
	}{
		{
			name: "Create a valid User",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				ScopeId:     defaultUser.GetScopeId(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateUserResponse{
				Uri: fmt.Sprintf("users/%s_", iam.UserPrefix),
				Item: &pb.User{
					ScopeId:           defaultUser.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: defaultUser.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Version:           1,
					AuthorizedActions: []string{"read", "update", "delete", "add-accounts", "set-accounts", "remove-accounts"},
				},
			},
		},
		{
			name: "Create a valid Global User",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				ScopeId:     scope.Global.String(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateUserResponse{
				Uri: fmt.Sprintf("users/%s_", iam.UserPrefix),
				Item: &pb.User{
					ScopeId:           scope.Global.String(),
					Scope:             &scopes.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Name:              &wrapperspb.StringValue{Value: "name"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					Version:           1,
					AuthorizedActions: []string{"read", "update", "delete", "add-accounts", "set-accounts", "remove-accounts"},
				},
			},
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				ScopeId: defaultUser.GetScopeId(),
				Id:      iam.UserPrefix + "_notallowed",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				ScopeId:     defaultUser.GetScopeId(),
				CreatedTime: ptypes.TimestampNow(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateUserRequest{Item: &pb.User{
				ScopeId:     defaultUser.GetScopeId(),
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := users.NewService(repoFn)
			require.NoError(err, "Error when getting new user service.")

			got, gErr := s.CreateUser(auth.DisabledAuthTestContext(repoFn, tc.req.GetItem().GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateUser(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
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
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateUser(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	u, repoFn := createDefaultUserAndRepo(t)
	tested, err := users.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service.")

	created, err := ptypes.Timestamp(u.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp")
	toMerge := &pbs.UpdateUserRequest{
		Id: u.GetPublicId(),
	}

	var version uint32 = 1

	resetUser := func() {
		repo, err := repoFn()
		require.NoError(t, err, "Couldn't get a new repo")
		version++ // From the test case that resulted in calling this
		u, _, _, err = repo.UpdateUser(context.Background(), u, version, []string{"Name", "Description"})
		require.NoError(t, err, "Failed to reset the user")
		version++
	}

	cases := []struct {
		name string
		req  *pbs.UpdateUserRequest
		res  *pbs.UpdateUserResponse
		err  error
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
					Id:                u.GetPublicId(),
					ScopeId:           u.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:       u.GetCreateTime().GetTimestamp(),
					AuthorizedActions: []string{"read", "update", "delete", "add-accounts", "set-accounts", "remove-accounts"},
				},
			},
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
					Id:                u.GetPublicId(),
					ScopeId:           u.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "new"},
					Description:       &wrapperspb.StringValue{Value: "desc"},
					CreatedTime:       u.GetCreateTime().GetTimestamp(),
					AuthorizedActions: []string{"read", "update", "delete", "add-accounts", "set-accounts", "remove-accounts"},
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateUserRequest{
				Item: &pb.User{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
					Id:                u.GetPublicId(),
					ScopeId:           u.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Description:       &wrapperspb.StringValue{Value: "default"},
					CreatedTime:       u.GetCreateTime().GetTimestamp(),
					AuthorizedActions: []string{"read", "update", "delete", "add-accounts", "set-accounts", "remove-accounts"},
				},
			},
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
					Id:                u.GetPublicId(),
					ScopeId:           u.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "updated"},
					Description:       &wrapperspb.StringValue{Value: "default"},
					CreatedTime:       u.GetCreateTime().GetTimestamp(),
					AuthorizedActions: []string{"read", "update", "delete", "add-accounts", "set-accounts", "remove-accounts"},
				},
			},
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
					Id:                u.GetPublicId(),
					ScopeId:           u.GetScopeId(),
					Scope:             &scopes.ScopeInfo{Id: u.GetScopeId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
					Name:              &wrapperspb.StringValue{Value: "default"},
					Description:       &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime:       u.GetCreateTime().GetTimestamp(),
					AuthorizedActions: []string{"read", "update", "delete", "add-accounts", "set-accounts", "remove-accounts"},
				},
			},
		},
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
			err: handlers.ApiErrorWithCode(codes.NotFound),
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
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.Item.Version = version

			assert, require := assert.New(t), require.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateUserRequest)
			proto.Merge(req, tc.req)

			// Test with bad version (too high, too low)
			req.Item.Version = version + 2
			_, gErr := tested.UpdateUser(auth.DisabledAuthTestContext(repoFn, u.GetScopeId()), req)
			require.Error(gErr)
			req.Item.Version = version - 1
			_, gErr = tested.UpdateUser(auth.DisabledAuthTestContext(repoFn, u.GetScopeId()), req)
			require.Error(gErr)
			req.Item.Version = version

			got, gErr := tested.UpdateUser(auth.DisabledAuthTestContext(repoFn, u.GetScopeId()), req)
			if tc.err != nil {
				require.Error(gErr)
				require.True(errors.Is(gErr, tc.err), "UpdateUser(%+v) got error %v, wanted %v", req, gErr, tc.err)
			} else {
				defer resetUser()
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateUser response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a user updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated user should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
				assert.Equal(version+1, got.GetItem().GetVersion())
				tc.res.Item.Version = version + 1
			}
			assert.Empty(cmp.Diff(tc.res, got, protocmp.Transform()), "UpdateUser(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestAddAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := users.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service.")

	o, _ := iam.TestScopes(t, iamRepo)
	amId := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0].GetPublicId()
	accts := password.TestAccounts(t, conn, amId, 3)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.PublicId, kms.KeyPurposeDatabase)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcAcct := oidc.TestAccount(t, conn, oidcAm, "test-subject")

	addCases := []struct {
		name           string
		setup          func(*iam.User)
		addAccounts    []string
		resultAccounts []string
		wantErr        bool
	}{
		{
			name:           "Add account on empty user",
			setup:          func(u *iam.User) {},
			addAccounts:    []string{accts[1].GetPublicId()},
			resultAccounts: []string{accts[1].GetPublicId()},
		},
		{
			name:           "Add oidc account on empty user",
			setup:          func(u *iam.User) {},
			addAccounts:    []string{oidcAcct.GetPublicId()},
			resultAccounts: []string{oidcAcct.GetPublicId()},
		},
		{
			name: "Add account on populated user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			addAccounts:    []string{accts[1].GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId(), accts[1].GetPublicId()},
		},
		{
			name: "Add duplicate account on populated user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			addAccounts:    []string{accts[1].GetPublicId(), accts[1].GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId(), accts[1].GetPublicId()},
		},
		{
			name: "Add empty on populated user",
			setup: func(u *iam.User) {
				iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), accts[1].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			wantErr: true,
		},
	}

	for _, tc := range addCases {
		t.Run(tc.name, func(t *testing.T) {
			usr := iam.TestUser(t, iamRepo, o.GetPublicId())
			defer func() {
				_, err := iamRepo.DeleteUser(context.Background(), usr.GetPublicId())
				require.NoError(t, err)
			}()
			tc.setup(usr)
			req := &pbs.AddUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: tc.addAccounts,
			}

			got, err := s.AddUserAccounts(auth.DisabledAuthTestContext(repoFn, o.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "Got error: %v", err)
			assert.ElementsMatch(t, got.GetItem().GetAccountIds(), tc.resultAccounts)
		})
	}

	usr := iam.TestUser(t, iamRepo, o.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.AddUserAccountsRequest
		err  error
	}{
		{
			name: "Bad user Id",
			req: &pbs.AddUserAccountsRequest{
				Id:      "bad id",
				Version: usr.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad account Id",
			req: &pbs.AddUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.AddUserAccounts(auth.DisabledAuthTestContext(repoFn, usr.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddUserAccounts(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestSetAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := users.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service.")

	o, _ := iam.TestScopes(t, iamRepo)
	amId := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0].GetPublicId()
	accts := password.TestAccounts(t, conn, amId, 3)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.PublicId, kms.KeyPurposeDatabase)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcAcct := oidc.TestAccount(t, conn, oidcAm, "test-subject")

	setCases := []struct {
		name           string
		setup          func(*iam.User)
		setAccounts    []string
		resultAccounts []string
		wantErr        bool
	}{
		{
			name:           "Set account on empty user",
			setup:          func(u *iam.User) {},
			setAccounts:    []string{accts[1].GetPublicId()},
			resultAccounts: []string{accts[1].GetPublicId()},
		},
		{
			name:           "Set oidc account on empty user",
			setup:          func(u *iam.User) {},
			setAccounts:    []string{oidcAcct.GetPublicId()},
			resultAccounts: []string{oidcAcct.GetPublicId()},
		},
		{
			name: "Set account on populated user",
			setup: func(u *iam.User) {
				iamRepo.AddUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			setAccounts:    []string{accts[1].GetPublicId()},
			resultAccounts: []string{accts[1].GetPublicId()},
		},
		{
			name: "Set duplicate account on populated user",
			setup: func(u *iam.User) {
				iamRepo.AddUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			setAccounts:    []string{accts[1].GetPublicId(), accts[1].GetPublicId()},
			resultAccounts: []string{accts[1].GetPublicId()},
		},
		{
			name: "Set empty on populated user",
			setup: func(u *iam.User) {
				iamRepo.AddUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), accts[1].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			setAccounts:    []string{},
			resultAccounts: nil,
		},
	}

	for _, tc := range setCases {
		t.Run(tc.name, func(t *testing.T) {
			usr := iam.TestUser(t, iamRepo, o.GetPublicId())
			defer func() {
				iamRepo.DeleteUser(context.Background(), usr.GetPublicId())
			}()

			tc.setup(usr)
			req := &pbs.SetUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: tc.setAccounts,
			}

			got, err := s.SetUserAccounts(auth.DisabledAuthTestContext(repoFn, o.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "Got error: %v", err)
			assert.ElementsMatch(t, got.GetItem().GetAccountIds(), tc.resultAccounts)
		})
	}

	usr := iam.TestUser(t, iamRepo, o.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.SetUserAccountsRequest
		err  error
	}{
		{
			name: "Bad User Id",
			req: &pbs.SetUserAccountsRequest{
				Id:      "bad id",
				Version: usr.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad account Id",
			req: &pbs.SetUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.SetUserAccounts(auth.DisabledAuthTestContext(repoFn, usr.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "SetUserAccounts(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}

func TestRemoveAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := users.NewService(repoFn)
	require.NoError(t, err, "Error when getting new user service.")

	o, _ := iam.TestScopes(t, iamRepo)
	amId := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0].GetPublicId()
	accts := password.TestAccounts(t, conn, amId, 3)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.PublicId, kms.KeyPurposeDatabase)
	oidcAm := oidc.TestAuthMethod(
		t, conn, databaseWrapper, o.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	oidcAcct := oidc.TestAccount(t, conn, oidcAm, "test-subject")

	addCases := []struct {
		name           string
		setup          func(*iam.User)
		removeAccounts []string
		resultAccounts []string
		wantErr        bool
	}{
		{
			name:           "Remove account on empty user",
			setup:          func(*iam.User) {},
			removeAccounts: []string{accts[1].GetPublicId()},
			wantErr:        true,
		},
		{
			name: "Remove 1 of 2 accounts from user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), accts[1].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			removeAccounts: []string{accts[1].GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId()},
		},
		{
			name: "Remove 1 oidc account of 2 accounts from user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), oidcAcct.GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			removeAccounts: []string{oidcAcct.GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId()},
		},
		{
			name: "Remove 1 duplicate accounts of 2 accounts from user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), accts[1].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			removeAccounts: []string{accts[1].GetPublicId(), accts[1].GetPublicId()},
			resultAccounts: []string{accts[0].GetPublicId()},
		},
		{
			name: "Remove all accounts from user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId(), accts[1].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			removeAccounts: []string{accts[0].GetPublicId(), accts[1].GetPublicId()},
			resultAccounts: []string{},
		},
		{
			name: "Remove empty on populated user",
			setup: func(u *iam.User) {
				_, err := iamRepo.SetUserAccounts(context.Background(), u.GetPublicId(), u.GetVersion(),
					[]string{accts[0].GetPublicId()})
				require.NoError(t, err)
				u.Version = u.Version + 1
			},
			wantErr: true,
		},
	}

	for _, tc := range addCases {
		t.Run(tc.name, func(t *testing.T) {
			usr := iam.TestUser(t, iamRepo, o.GetPublicId())
			defer func() {
				iamRepo.DeleteUser(context.Background(), usr.GetPublicId())
			}()
			tc.setup(usr)
			req := &pbs.RemoveUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: tc.removeAccounts,
			}

			got, err := s.RemoveUserAccounts(auth.DisabledAuthTestContext(repoFn, o.GetPublicId()), req)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "Got error: %v", err)

			assert.ElementsMatch(t, got.GetItem().GetAccountIds(), tc.resultAccounts)
		})
	}

	usr := iam.TestUser(t, iamRepo, o.GetPublicId())

	failCases := []struct {
		name string
		req  *pbs.RemoveUserAccountsRequest
		err  error
	}{
		{
			name: "Bad User Id",
			req: &pbs.RemoveUserAccountsRequest{
				Id:      "bad id",
				Version: usr.GetVersion(),
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Bad account Id",
			req: &pbs.RemoveUserAccountsRequest{
				Id:         usr.GetPublicId(),
				Version:    usr.GetVersion(),
				AccountIds: []string{"invalid"},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, gErr := s.RemoveUserAccounts(auth.DisabledAuthTestContext(repoFn, usr.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "AddUserAccounts(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
		})
	}
}
