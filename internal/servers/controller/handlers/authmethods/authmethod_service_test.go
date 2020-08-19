package authmethods_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	scopepb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	wantU := &pb.AuthMethod{
		Id:          am.GetPublicId(),
		CreatedTime: am.CreateTime.GetTimestamp(),
		UpdatedTime: am.UpdateTime.GetTimestamp(),
		Type:        "password",
		Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
			"min_password_length":   structpb.NewNumberValue(8),
			"min_login_name_length": structpb.NewNumberValue(3),
		}},
		Version: 1,
		Scope: &scopepb.ScopeInfo{
			Id:   o.GetPublicId(),
			Type: o.GetType(),
		},
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetAuthMethodRequest
		res     *pbs.GetAuthMethodResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing AuthMethod",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: am.GetPublicId()},
			res:     &pbs.GetAuthMethodResponse{Item: wantU},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existant AuthMethod",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: password.AuthMethodPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: password.AuthMethodPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := authmethods.NewService(repoFn)
			require.NoError(err, "Couldn't create new auth_method service.")

			got, gErr := s.GetAuthMethod(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	oNoAuthMethods, _ := iam.TestScopes(t, conn)
	oWithAuthMethods, _ := iam.TestScopes(t, conn)
	oWithOtherAuthMethods, _ := iam.TestScopes(t, conn)

	var wantSomeAuthMethods []*pb.AuthMethod
	for _, am := range password.TestAuthMethods(t, conn, oWithAuthMethods.GetPublicId(), 3) {
		wantSomeAuthMethods = append(wantSomeAuthMethods, &pb.AuthMethod{
			Id:          am.GetPublicId(),
			CreatedTime: am.GetCreateTime().GetTimestamp(),
			UpdatedTime: am.GetUpdateTime().GetTimestamp(),
			Scope:       &scopepb.ScopeInfo{Id: oWithAuthMethods.GetPublicId(), Type: scope.Org.String()},
			Version:     1,
			Type:        "password",
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"min_password_length":   structpb.NewNumberValue(8),
				"min_login_name_length": structpb.NewNumberValue(3),
			}},
		})
	}

	var wantOtherAuthMethods []*pb.AuthMethod
	for _, aa := range password.TestAuthMethods(t, conn, oWithOtherAuthMethods.GetPublicId(), 3) {
		wantOtherAuthMethods = append(wantOtherAuthMethods, &pb.AuthMethod{
			Id:          aa.GetPublicId(),
			CreatedTime: aa.GetCreateTime().GetTimestamp(),
			UpdatedTime: aa.GetUpdateTime().GetTimestamp(),
			Scope:       &scopepb.ScopeInfo{Id: oWithOtherAuthMethods.GetPublicId(), Type: scope.Org.String()},
			Version:     1,
			Type:        "password",
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"min_password_length":   structpb.NewNumberValue(8),
				"min_login_name_length": structpb.NewNumberValue(3),
			}},
		})
	}

	cases := []struct {
		name    string
		scopeId string
		res     *pbs.ListAuthMethodsResponse
		errCode codes.Code
	}{
		{
			name:    "List Some Auth Methods",
			scopeId: oWithAuthMethods.GetPublicId(),
			res:     &pbs.ListAuthMethodsResponse{Items: wantSomeAuthMethods},
			errCode: codes.OK,
		},
		{
			name:    "List Other Auth Methods",
			scopeId: oWithOtherAuthMethods.GetPublicId(),
			res:     &pbs.ListAuthMethodsResponse{Items: wantOtherAuthMethods},
			errCode: codes.OK,
		},
		{
			name:    "List No Auth Methods",
			scopeId: oNoAuthMethods.GetPublicId(),
			res:     &pbs.ListAuthMethodsResponse{},
			errCode: codes.OK,
		},
		// TODO: When an auth method doesn't exist, we should return a 404 instead of an empty list.
		{
			name:    "Unfound Auth Method",
			scopeId: password.AuthMethodPrefix + "_DoesntExis",
			res:     &pbs.ListAuthMethodsResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := authmethods.NewService(repoFn)
			require.NoError(err, "Couldn't create new auth_method service.")

			got, gErr := s.ListAuthMethods(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), &pbs.ListAuthMethodsRequest{})
			assert.Equal(tc.errCode, status.Code(gErr), "ListAuthMethods() for scope %q got error %v, wanted %v", tc.scopeId, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListAuthMethods() for scope %q got response %q, wanted %q", tc.scopeId, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	s, err := authmethods.NewService(repoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	cases := []struct {
		name    string
		req     *pbs.DeleteAuthMethodRequest
		res     *pbs.DeleteAuthMethodResponse
		errCode codes.Code
	}{
		{
			name: "Delete an Existing AuthMethod",
			req: &pbs.DeleteAuthMethodRequest{
				Id: am.GetPublicId(),
			},
			res: &pbs.DeleteAuthMethodResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad auth_method id",
			req: &pbs.DeleteAuthMethodRequest{
				Id: password.AuthMethodPrefix + "_doesntexis",
			},
			res: &pbs.DeleteAuthMethodResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad AuthMethod Id formatting",
			req: &pbs.DeleteAuthMethodRequest{
				Id: "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteAuthMethod(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	s, err := authmethods.NewService(repoFn)
	require.NoError(err, "Error when getting new auth_method service.")

	req := &pbs.DeleteAuthMethodRequest{
		Id: am.GetPublicId(),
	}
	got, gErr := s.DeleteAuthMethod(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteAuthMethod(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	defaultAm := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	defaultCreated, err := ptypes.Timestamp(defaultAm.GetCreateTime().GetTimestamp())
	require.NoError(t, err, "Error converting proto to timestamp.")

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
				Type:        "password",
			}},
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("scopes/%s/auth-methods/%s_", o.GetPublicId(), password.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Scope:       &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType()},
					Version:     1,
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				Id:   password.AuthMethodPrefix + "_notallowed",
				Type: "password",
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
				Type:        "password",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				UpdatedTime: ptypes.TimestampNow(),
				Type:        "password",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Must specify type",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				Name:        &wrapperspb.StringValue{Value: "must specify type"},
				Description: &wrapperspb.StringValue{Value: "must specify type"},
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Attributes must be valid for type",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				Name:        &wrapperspb.StringValue{Value: "Attributes must be valid for type"},
				Description: &wrapperspb.StringValue{Value: "Attributes must be valid for type"},
				Type:        "password",
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"invalid_field":         structpb.NewStringValue("invalid_value"),
					"min_login_name_length": structpb.NewNumberValue(3),
				}},
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := authmethods.NewService(repoFn)
			require.NoError(err, "Error when getting new auth_method service.")

			got, gErr := s.CreateAuthMethod(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			if tc.res == nil {
				require.Nil(got)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), password.AuthMethodPrefix+"_"))
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
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, wrap)
	}

	o, _ := iam.TestScopes(t, conn)
	tested, err := authmethods.NewService(repoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType()}

	freshAuthMethod := func() (*pb.AuthMethod, func()) {
		am, err := tested.CreateAuthMethod(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())),
			&pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				Name:        wrapperspb.String("default"),
				Description: wrapperspb.String("default"),
				Type:        "password",
			}})
		require.NoError(t, err)

		clean := func() {
			_, err := tested.DeleteAuthMethod(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())),
				&pbs.DeleteAuthMethodRequest{Id: am.GetItem().GetId()})
			require.NoError(t, err)
		}

		return am.GetItem(), clean
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
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope: defaultScopeInfo,
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
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope: defaultScopeInfo,
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
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope: defaultScopeInfo,
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
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope: defaultScopeInfo,
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
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope: defaultScopeInfo,
				},
			},
			errCode: codes.OK,
		},
		// TODO: Updating a non existant auth_method should result in a NotFound exception but currently results in
		// the repoFn returning an internal error.
		{
			name: "Update a Non Existing AuthMethod",
			req: &pbs.UpdateAuthMethodRequest{
				Id: password.AuthMethodPrefix + "_DoesntExis",
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
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.AuthMethod{
					Id:          password.AuthMethodPrefix + "_somethinge",
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
		{
			name: "Cant specify Type",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"type"},
				},
				Item: &pb.AuthMethod{
					Type: "oidc",
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Update login name length",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.min_login_name_length"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_login_name_length": structpb.NewNumberValue(42),
						"min_password_length":   structpb.NewNumberValue(55555),
					}},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(42),
					}},
					Scope: defaultScopeInfo,
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update password length",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.min_password_length"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_login_name_length": structpb.NewNumberValue(5555),
						"min_password_length":   structpb.NewNumberValue(42),
					}},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(42),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope: defaultScopeInfo,
				},
			},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			am, cleanup := freshAuthMethod()
			defer cleanup()

			tc.req.Item.Version = 1

			if tc.req.GetId() == "" {
				tc.req.Id = am.GetId()
			}

			if tc.res != nil && tc.res.Item != nil {
				tc.res.Item.Id = am.GetId()
				tc.res.Item.CreatedTime = am.GetCreatedTime()
			}

			got, gErr := tested.UpdateAuthMethod(auth.DisabledAuthTestContext(auth.WithScopeId(o.GetPublicId())), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)

			if tc.res == nil {
				require.Nil(got)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateAuthMethod response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")

				created, err := ptypes.Timestamp(am.GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp")

				// Verify it is a auth_method updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated auth_method should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

				assert.EqualValues(2, got.Item.Version)
				tc.res.Item.Version = 2
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "UpdateAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}
