package auth_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/watchtower/internal/auth/password"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/auth"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/auth"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createDefaultAuthMethodAndRepo(t *testing.T) (*password.AuthMethod, func() (*password.Repository, error)) {
	t.Helper()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	am := password.testAuthMethod(t, conn, o.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	return am, repoFn
}

func TestGet(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	am, repo := createDefaultAuthMethodAndRepo(t)
	toMerge := &pbs.GetAuthMethodRequest{
		OrgId: am.GetScopeId(),
		Id:    am.GetPublicId(),
	}

	wantU := &pb.AuthMethod{
		Id:          am.GetPublicId(),
		Name:        &wrapperspb.StringValue{Value: am.GetName()},
		Description: &wrapperspb.StringValue{Value: am.GetDescription()},
		CreatedTime: am.CreateTime.GetTimestamp(),
		UpdatedTime: am.UpdateTime.GetTimestamp(),
	}

	cases := []struct {
		name    string
		req     *pbs.GetAuthMethodRequest
		res     *pbs.GetAuthMethodResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing AuthMethod",
			req:     &pbs.GetAuthMethodRequest{Id: am.GetPublicId()},
			res:     &pbs.GetAuthMethodResponse{Item: wantU},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existant AuthMethod",
			req:     &pbs.GetAuthMethodRequest{Id: iam.AuthMethodPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetAuthMethodRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetAuthMethodRequest{Id: iam.AuthMethodPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetAuthMethodRequest)
			proto.Merge(req, tc.req)

			s, err := auth.NewService(repo)
			require.NoError(err, "Couldn't create new auth_method service.")

			got, gErr := s.GetAuthMethod(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetAuthMethod(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetAuthMethod(%q) got response %q, wanted %q", req, got, tc.res)
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

	oNoAuthMethods, _ := iam.TestScopes(t, conn)
	oWithAuthMethods, _ := iam.TestScopes(t, conn)

	var wantAuthMethods []*pb.AuthMethod
	for i := 0; i < 10; i++ {
		newU, err := password.NewAuthMethod(oWithAuthMethods.GetPublicId())
		require.NoError(err)
		am, err := repo.CreateAuthMethod(context.Background(), newU)
		require.NoError(err)
		wantAuthMethods = append(wantAuthMethods, &pb.AuthMethod{
			Id:          am.GetPublicId(),
			CreatedTime: am.GetCreateTime().GetTimestamp(),
			UpdatedTime: am.GetUpdateTime().GetTimestamp(),
		})
	}

	cases := []struct {
		name    string
		req     *pbs.ListAuthMethodsRequest
		res     *pbs.ListAuthMethodsResponse
		errCode codes.Code
	}{
		{
			name:    "List Many AuthMethods",
			req:     &pbs.ListAuthMethodsRequest{OrgId: oWithAuthMethods.GetPublicId()},
			res:     &pbs.ListAuthMethodsResponse{Items: wantAuthMethods},
			errCode: codes.OK,
		},
		{
			name:    "List No AuthMethods",
			req:     &pbs.ListAuthMethodsRequest{OrgId: oNoAuthMethods.GetPublicId()},
			res:     &pbs.ListAuthMethodsResponse{},
			errCode: codes.OK,
		},
		{
			name:    "Invalid Org Id",
			req:     &pbs.ListAuthMethodsRequest{OrgId: iam.AuthMethodPrefix + "_this is invalid"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		// TODO: When an org doesn't exist, we should return a 404 instead of an empty list.
		{
			name:    "Unfound Org",
			req:     &pbs.ListAuthMethodsRequest{OrgId: scope.Organization.Prefix() + "_DoesntExis"},
			res:     &pbs.ListAuthMethodsResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := auth.NewService(repoFn)
			require.NoError(err, "Couldn't create new auth_method service.")

			got, gErr := s.ListAuthMethods(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "ListAuthMethods(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "ListAuthMethods(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	require := require.New(t)
	am, repo := createDefaultAuthMethodAndRepo(t)

	s, err := auth.NewService(repo)
	require.NoError(err, "Error when getting new auth_method service.")

	cases := []struct {
		name    string
		req     *pbs.DeleteAuthMethodRequest
		res     *pbs.DeleteAuthMethodResponse
		errCode codes.Code
	}{
		{
			name: "Delete an Existing AuthMethod",
			req: &pbs.DeleteAuthMethodRequest{
				OrgId: am.GetScopeId(),
				Id:    am.GetPublicId(),
			},
			res: &pbs.DeleteAuthMethodResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad auth_method id",
			req: &pbs.DeleteAuthMethodRequest{
				OrgId: am.GetScopeId(),
				Id:    iam.AuthMethodPrefix + "_doesntexis",
			},
			res: &pbs.DeleteAuthMethodResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad org id",
			req: &pbs.DeleteAuthMethodRequest{
				OrgId: "o_doesntexis",
				Id:    am.GetPublicId(),
			},
			res: &pbs.DeleteAuthMethodResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad org formatting",
			req: &pbs.DeleteAuthMethodRequest{
				OrgId: "bad_format",
				Id:    am.GetPublicId(),
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad AuthMethod Id formatting",
			req: &pbs.DeleteAuthMethodRequest{
				OrgId: am.GetScopeId(),
				Id:    "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteAuthMethod(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	am, repo := createDefaultAuthMethodAndRepo(t)

	s, err := auth.NewService(repo)
	require.NoError(err, "Error when getting new auth_method service")
	req := &pbs.DeleteAuthMethodRequest{
		OrgId: am.GetScopeId(),
		Id:    am.GetPublicId(),
	}
	got, gErr := s.DeleteAuthMethod(context.Background(), req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteAuthMethod(context.Background(), req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	require := require.New(t)
	defaultAuthMethod, repo := createDefaultAuthMethodAndRepo(t)
	defaultCreated, err := ptypes.Timestamp(defaultAuthMethod.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp.")
	toMerge := &pbs.CreateAuthMethodRequest{
		OrgId: defaultAuthMethod.GetScopeId(),
	}

	cases := []struct {
		name    string
		req     *pbs.CreateAuthMethodRequest
		res     *pbs.CreateAuthMethodResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid AuthMethod",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("orgs/%s/auth_methods/u_", defaultAuthMethod.GetScopeId()),
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				Id: iam.AuthMethodPrefix + "_notallowed",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateAuthMethodRequest)
			proto.Merge(req, tc.req)

			s, err := auth.NewService(repo)
			require.NoError(err, "Error when getting new auth_method service.")

			got, gErr := s.CreateAuthMethod(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateAuthMethod(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			if got != nil {
				assert.True(strings.HasPrefix(got.GetUri(), tc.res.Uri))
				assert.True(strings.HasPrefix(got.GetItem().GetId(), iam.AuthMethodPrefix+"_"))
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				// Verify it is a auth_method created after the test setup's default auth_method
				assert.True(gotCreateTime.After(defaultCreated), "New auth_method should have been created after default auth_method. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.After(defaultCreated), "New auth_method should have been updated after default auth_method. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.True(proto.Equal(got, tc.res), "CreateAuthMethod(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	require := require.New(t)
	am, repoFn := createDefaultAuthMethodAndRepo(t)
	tested, err := auth.NewService(repoFn)
	require.NoError(err, "Error when getting new auth_method service.")

	resetAuthMethod := func() {
		repo, err := repoFn()
		require.NoError(err, "Couldn't get a new repo")
		am, _, err = repo.UpdateAuthMethod(context.Background(), am, []string{"Name", "Description"})
		require.NoError(err, "Failed to reset the auth_method")
	}

	created, err := ptypes.Timestamp(am.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp")
	toMerge := &pbs.UpdateAuthMethodRequest{
		OrgId: am.GetScopeId(),
		Id:    am.GetPublicId(),
	}

	cases := []struct {
		name    string
		req     *pbs.UpdateAuthMethodRequest
		res     *pbs.UpdateAuthMethodResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing AuthMethod",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					Id:          am.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: am.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					Id:          am.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: am.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateAuthMethodRequest{
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.AuthMethod{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					Id:          am.GetPublicId(),
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: am.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					Id:          am.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: am.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					Id:          am.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime: am.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		// TODO: Updating a non existant auth_method should result in a NotFound exception but currently results in
		// the repoFn returning an internal error.
		{
			name: "Update a Non Existing AuthMethod",
			req: &pbs.UpdateAuthMethodRequest{
				Id: iam.AuthMethodPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.Internal,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateAuthMethodRequest{
				Id: am.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.AuthMethod{
					Id:          iam.AuthMethodPrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.AuthMethod{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.AuthMethod{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer resetAuthMethod()
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateAuthMethodRequest)
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateAuthMethod(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateAuthMethod(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateAuthMethod response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a auth_method updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated auth_method should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			assert.True(proto.Equal(got, tc.res), "UpdateAuthMethod(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
