package authmethods_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	scopepb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/scope"
	capoidc "github.com/hashicorp/cap/oidc"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPassword  = "thetestpassword"
	testLoginName = "default"
)

var (
	pwAuthorizedActions = []string{
		action.Read.String(),
		action.Update.String(),
		action.Delete.String(),
		action.Authenticate.String(),
	}
	oidcAuthorizedActions = []string{
		action.Read.String(),
		action.Update.String(),
		action.Delete.String(),
		action.ChangeState.String(),
		action.Authenticate.String(),
	}
)

var authorizedCollectionActions = map[string]*structpb.ListValue{
	"accounts": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
}

func TestGet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kmsCache)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	wantPw := &pb.AuthMethod{
		Id:          am.GetPublicId(),
		ScopeId:     am.GetScopeId(),
		CreatedTime: am.CreateTime.GetTimestamp(),
		UpdatedTime: am.UpdateTime.GetTimestamp(),
		Type:        "password",
		Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
			"min_password_length":   structpb.NewNumberValue(8),
			"min_login_name_length": structpb.NewNumberValue(3),
		}},
		Version: 1,
		Scope: &scopepb.ScopeInfo{
			Id:            o.GetPublicId(),
			Type:          o.GetType(),
			ParentScopeId: scope.Global.String(),
		},
		AuthorizedActions:           pwAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
	}

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcam := oidc.TestAuthMethod(t, conn, databaseWrapper, o.GetPublicId(), oidc.InactiveState, oidc.TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "secret")

	wantOidc := &pb.AuthMethod{
		Id:          oidcam.GetPublicId(),
		ScopeId:     oidcam.GetScopeId(),
		CreatedTime: oidcam.CreateTime.GetTimestamp(),
		UpdatedTime: oidcam.UpdateTime.GetTimestamp(),
		Type:        auth.OidcSubtype.String(),
		Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
			"issuer":             structpb.NewStringValue("https://alice.com"),
			"client_id":          structpb.NewStringValue("alice_rp"),
			"client_secret_hmac": structpb.NewStringValue("<hmac>"),
			"state":              structpb.NewStringValue(string(oidc.InactiveState)),
		}},
		Version: 1,
		Scope: &scopepb.ScopeInfo{
			Id:            o.GetPublicId(),
			Type:          o.GetType(),
			ParentScopeId: scope.Global.String(),
		},
		AuthorizedActions:           oidcAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetAuthMethodRequest
		res     *pbs.GetAuthMethodResponse
		err     error
	}{
		{
			name:    "Get an Existing PW AuthMethod",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: am.GetPublicId()},
			res:     &pbs.GetAuthMethodResponse{Item: wantPw},
		},
		{
			name:    "Get an Existing OIDC AuthMethod",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: oidcam.GetPublicId()},
			res:     &pbs.GetAuthMethodResponse{Item: wantOidc},
		},
		{
			name:    "Get a non existant AuthMethod",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: password.AuthMethodPrefix + "_DoesntExis"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Wrong id prefix",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: "j_1234567890"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "space in id",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: password.AuthMethodPrefix + "_1 23456789"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := authmethods.NewService(kmsCache, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
			require.NoError(err, "Couldn't create new auth_method service.")

			got, gErr := s.GetAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if _, ok := got.Item.Attributes.Fields["client_secret_hmac"]; ok {
				assert.NotEqual("secret", got.Item.Attributes.Fields["client_secret_hmac"])
				got.Item.Attributes.Fields["client_secret_hmac"] = structpb.NewStringValue("<hmac>")
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kmsCache)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	oNoAuthMethods, _ := iam.TestScopes(t, iamRepo)
	oWithAuthMethods, _ := iam.TestScopes(t, iamRepo)
	oWithOtherAuthMethods, _ := iam.TestScopes(t, iamRepo)

	var wantSomeAuthMethods []*pb.AuthMethod
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), oWithAuthMethods.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcam := oidc.TestAuthMethod(t, conn, databaseWrapper, oWithAuthMethods.GetPublicId(), oidc.InactiveState, oidc.TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "secret")
	wantSomeAuthMethods = append(wantSomeAuthMethods, &pb.AuthMethod{
		Id:          oidcam.GetPublicId(),
		ScopeId:     oWithAuthMethods.GetPublicId(),
		CreatedTime: oidcam.GetCreateTime().GetTimestamp(),
		UpdatedTime: oidcam.GetUpdateTime().GetTimestamp(),
		Scope:       &scopepb.ScopeInfo{Id: oWithAuthMethods.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Version:     1,
		Type:        auth.OidcSubtype.String(),
		Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
			"issuer":             structpb.NewStringValue("https://alice.com"),
			"client_id":          structpb.NewStringValue("alice_rp"),
			"client_secret_hmac": structpb.NewStringValue("<hmac>"),
			"state":              structpb.NewStringValue(string(oidc.InactiveState)),
		}},
		AuthorizedActions:           oidcAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
	})

	for _, am := range password.TestAuthMethods(t, conn, oWithAuthMethods.GetPublicId(), 3) {
		wantSomeAuthMethods = append(wantSomeAuthMethods, &pb.AuthMethod{
			Id:          am.GetPublicId(),
			ScopeId:     oWithAuthMethods.GetPublicId(),
			CreatedTime: am.GetCreateTime().GetTimestamp(),
			UpdatedTime: am.GetUpdateTime().GetTimestamp(),
			Scope:       &scopepb.ScopeInfo{Id: oWithAuthMethods.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:     1,
			Type:        "password",
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"min_password_length":   structpb.NewNumberValue(8),
				"min_login_name_length": structpb.NewNumberValue(3),
			}},
			AuthorizedActions:           pwAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions,
		})
	}

	var wantOtherAuthMethods []*pb.AuthMethod
	for _, aa := range password.TestAuthMethods(t, conn, oWithOtherAuthMethods.GetPublicId(), 3) {
		wantOtherAuthMethods = append(wantOtherAuthMethods, &pb.AuthMethod{
			Id:          aa.GetPublicId(),
			ScopeId:     oWithOtherAuthMethods.GetPublicId(),
			CreatedTime: aa.GetCreateTime().GetTimestamp(),
			UpdatedTime: aa.GetUpdateTime().GetTimestamp(),
			Scope:       &scopepb.ScopeInfo{Id: oWithOtherAuthMethods.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:     1,
			Type:        "password",
			Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
				"min_password_length":   structpb.NewNumberValue(8),
				"min_login_name_length": structpb.NewNumberValue(3),
			}},
			AuthorizedActions:           pwAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions,
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListAuthMethodsRequest
		res  *pbs.ListAuthMethodsResponse
		err  error
	}{
		{
			name: "List Some Auth Methods",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: oWithAuthMethods.GetPublicId()},
			res:  &pbs.ListAuthMethodsResponse{Items: wantSomeAuthMethods},
		},
		{
			name: "List Other Auth Methods",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: oWithOtherAuthMethods.GetPublicId()},
			res:  &pbs.ListAuthMethodsResponse{Items: wantOtherAuthMethods},
		},
		{
			name: "List No Auth Methods",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: oNoAuthMethods.GetPublicId()},
			res:  &pbs.ListAuthMethodsResponse{},
		},
		{
			name: "Unfound Auth Method",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: "o_DoesntExis"},
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "List All Auth Methods Recursively",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: "global", Recursive: true},
			res: &pbs.ListAuthMethodsResponse{
				Items: append(wantSomeAuthMethods, wantOtherAuthMethods...),
			},
		},
		{
			name: "Filter To Some Auth Methods",
			req: &pbs.ListAuthMethodsRequest{
				ScopeId: "global", Recursive: true,
				Filter: fmt.Sprintf(`"/item/scope/id"==%q`, oWithAuthMethods.GetPublicId()),
			},
			res: &pbs.ListAuthMethodsResponse{Items: wantSomeAuthMethods},
		},
		{
			name: "Filter All Auth Methods",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: oWithAuthMethods.GetPublicId(), Filter: `"/item/id"=="nothingmatchesthis"`},
			res:  &pbs.ListAuthMethodsResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: oWithAuthMethods.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := authmethods.NewService(kmsCache, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
			require.NoError(err, "Couldn't create new auth_method service.")

			got, gErr := s.ListAuthMethods(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListAuthMethods() for scope %q got error %v, wanted %v", tc.req.GetScopeId(), gErr, tc.err)
				return
			}
			require.NoError(gErr)
			for i, g := range got.Items {
				if _, ok := g.Attributes.Fields["client_secret_hmac"]; ok {
					assert.NotEqual("secret", g.Attributes.Fields["client_secret_hmac"])
					delete(g.Attributes.Fields, "client_secret_hmac")
					delete(tc.res.Items[i].Attributes.Fields, "client_secret_hmac")
				}
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ListAuthMethods() for scope %q got response %q, wanted %q", tc.req.GetScopeId(), got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kmsCache)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	pwam := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.GetPublicId(), kms.KeyPurposeDatabase)
	oidcam := oidc.TestAuthMethod(t, conn, databaseWrapper, o.GetPublicId(), oidc.InactiveState, oidc.TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "my-dogs-name")

	s, err := authmethods.NewService(kmsCache, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	cases := []struct {
		name string
		req  *pbs.DeleteAuthMethodRequest
		res  *pbs.DeleteAuthMethodResponse
		err  error
	}{
		{
			name: "Delete an Existing PW AuthMethod",
			req: &pbs.DeleteAuthMethodRequest{
				Id: pwam.GetPublicId(),
			},
			res: &pbs.DeleteAuthMethodResponse{},
		},
		{
			name: "Delete an Existing OIDC AuthMethod",
			req: &pbs.DeleteAuthMethodRequest{
				Id: oidcam.GetPublicId(),
			},
			res: &pbs.DeleteAuthMethodResponse{},
		},
		{
			name: "Delete bad auth_method id",
			req: &pbs.DeleteAuthMethodRequest{
				Id: password.AuthMethodPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Bad AuthMethod Id formatting",
			req: &pbs.DeleteAuthMethodRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	s, err := authmethods.NewService(kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
	require.NoError(err, "Error when getting new auth_method service.")

	req := &pbs.DeleteAuthMethodRequest{
		Id: am.GetPublicId(),
	}
	_, gErr := s.DeleteAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	defaultAm := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	defaultCreated := defaultAm.GetCreateTime().GetTimestamp()

	cases := []struct {
		name     string
		req      *pbs.CreateAuthMethodRequest
		res      *pbs.CreateAuthMethodResponse
		idPrefix string
		err      error
	}{
		{
			name: "Create a valid Password AuthMethod",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
				Type:        "password",
			}},
			idPrefix: password.AuthMethodPrefix + "_",
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("auth-methods/%s_", password.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					ScopeId:     o.GetPublicId(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Scope:       &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()},
					Version:     1,
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Create a valid OIDC AuthMethod",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"issuer":         structpb.NewStringValue("https://example.discovery.url:4821/.well-known/openid-configuration/"),
					"client_id":      structpb.NewStringValue("someclientid"),
					"client_secret":  structpb.NewStringValue("secret"),
					"api_url_prefix": structpb.NewStringValue("https://callback.prefix:9281/path"),
					"allowed_audiences": func() *structpb.Value {
						lv, _ := structpb.NewList([]interface{}{"foo", "bar"})
						return structpb.NewListValue(lv)
					}(),
				}},
			}},
			idPrefix: oidc.AuthMethodPrefix + "_",
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("auth-methods/%s_", oidc.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					ScopeId:     o.GetPublicId(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Scope:       &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()},
					Version:     1,
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"issuer":             structpb.NewStringValue("https://example.discovery.url:4821"),
						"client_id":          structpb.NewStringValue("someclientid"),
						"client_secret_hmac": structpb.NewStringValue("<hmac>"),
						"state":              structpb.NewStringValue(string(oidc.InactiveState)),
						"api_url_prefix":     structpb.NewStringValue("https://callback.prefix:9281/path"),
						"callback_url":       structpb.NewStringValue(fmt.Sprintf("https://callback.prefix:9281/path/v1/auth-methods/%s_[0-9A-z]*:authenticate:callback", oidc.AuthMethodPrefix)),
						"allowed_audiences": func() *structpb.Value {
							lv, _ := structpb.NewList([]interface{}{"foo", "bar"})
							return structpb.NewListValue(lv)
						}(),
					}},
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Create a global Password AuthMethod",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     scope.Global.String(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
				Type:        "password",
			}},
			idPrefix: password.AuthMethodPrefix + "_",
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("auth-methods/%s_", password.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					ScopeId:     scope.Global.String(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Scope:       &scopepb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Version:     1,
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Create a global OIDC AuthMethod",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: scope.Global.String(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"issuer":        structpb.NewStringValue("https://example.discovery.url"),
					"client_id":     structpb.NewStringValue("someclientid"),
					"client_secret": structpb.NewStringValue("secret"),
				}},
			}},
			idPrefix: oidc.AuthMethodPrefix + "_",
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("auth-methods/%s_", oidc.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					ScopeId:     scope.Global.String(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Scope:       &scopepb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Version:     1,
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"issuer":             structpb.NewStringValue("https://example.discovery.url"),
						"client_id":          structpb.NewStringValue("someclientid"),
						"client_secret_hmac": structpb.NewStringValue("<hmac>"),
						"state":              structpb.NewStringValue(string(oidc.InactiveState)),
					}},
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Id:      password.AuthMethodPrefix + "_notallowed",
				Type:    "password",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				CreatedTime: timestamppb.Now(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				UpdatedTime: timestamppb.Now(),
				Type:        "password",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				UpdatedTime: timestamppb.Now(),
				Type:        "password",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify type",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "must specify type"},
				Description: &wrapperspb.StringValue{Value: "must specify type"},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Attributes must be valid for password type",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "Attributes must be valid for type"},
				Description: &wrapperspb.StringValue{Value: "Attributes must be valid for type"},
				Type:        auth.PasswordSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"invalid_field":         structpb.NewStringValue("invalid_value"),
					"min_login_name_length": structpb.NewNumberValue(3),
				}},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Attributes must be valid for oidc type",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "Attributes must be valid for type"},
				Description: &wrapperspb.StringValue{Value: "Attributes must be valid for type"},
				Type:        auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"login-name": structpb.NewStringValue("invalid_value"),
					"password":   structpb.NewNumberValue(3),
				}},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod Doesn't Require Issuer",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"client_id":     structpb.NewStringValue("someclientid"),
					"client_secret": structpb.NewStringValue("secret"),
				}},
			}},
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("auth-methods/%s_", oidc.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					ScopeId:     o.GetPublicId(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Scope:       &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()},
					Version:     1,
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"client_id":          structpb.NewStringValue("someclientid"),
						"client_secret_hmac": structpb.NewStringValue("<hmac>"),
						"state":              structpb.NewStringValue(string(oidc.InactiveState)),
					}},
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "OIDC AuthMethod Requires Client Id",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"issuer":        structpb.NewStringValue("https://example.discovery.url:4821/.well-known/openid-configuration/"),
					"client_secret": structpb.NewStringValue("secret"),
				}},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod Requires Client Secret",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"issuer":    structpb.NewStringValue("https://example.discovery.url:4821/.well-known/openid-configuration/"),
					"client_id": structpb.NewStringValue("someclientid"),
				}},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod cant specify client secret hmac",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"issuer":             structpb.NewStringValue("https://example.discovery.url:4821/.well-known/openid-configuration/"),
					"client_id":          structpb.NewStringValue("someclientid"),
					"client_secret":      structpb.NewStringValue("secret"),
					"client_secret_hmac": structpb.NewStringValue("hmac"),
				}},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod cant specify state",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"issuer":        structpb.NewStringValue("https://example.discovery.url:4821/.well-known/openid-configuration/"),
					"client_id":     structpb.NewStringValue("someclientid"),
					"client_secret": structpb.NewStringValue("secret"),
					"state":         structpb.NewStringValue(string(oidc.InactiveState)),
				}},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod Must Match Standard Alg Names",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"issuer":        structpb.NewStringValue("https://example2.discovery.url:4821"),
					"client_id":     structpb.NewStringValue("someclientid"),
					"client_secret": structpb.NewStringValue("secret"),
					"signing_algorithms": func() *structpb.Value {
						lv, _ := structpb.NewList([]interface{}{string(oidc.ES256), strings.ToLower(string(oidc.EdDSA))})
						return structpb.NewListValue(lv)
					}(),
				}},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod API Urls Prefix Format",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"issuer":         structpb.NewStringValue("https://example2.discovery.url:4821"),
					"client_id":      structpb.NewStringValue("someclientid"),
					"client_secret":  structpb.NewStringValue("secret"),
					"api_url_prefix": structpb.NewStringValue("invalid path"),
				}},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod Callback Url Read Only",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"issuer":        structpb.NewStringValue("https://example2.discovery.url:4821"),
					"client_id":     structpb.NewStringValue("someclientid"),
					"client_secret": structpb.NewStringValue("secret"),
					"callback_url":  structpb.NewStringValue("http://another.url.com:82471"),
				}},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod unparseable certificates",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    auth.OidcSubtype.String(),
				Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
					"issuer":        structpb.NewStringValue("https://example2.discovery.url:4821"),
					"client_id":     structpb.NewStringValue("someclientid"),
					"client_secret": structpb.NewStringValue("secret"),
					"certificates": func() *structpb.Value {
						lv, _ := structpb.NewList([]interface{}{"unparseable"})
						return structpb.NewListValue(lv)
					}(),
				}},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := authmethods.NewService(kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
			require.NoError(err, "Error when getting new auth_method service.")

			got, gErr := s.CreateAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetItem().GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if tc.res == nil {
				require.Nil(got)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), tc.idPrefix))
				gotCreateTime := got.GetItem().GetCreatedTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime()

				// Verify it is a auth_method created after the test setup's default auth_method
				assert.True(gotCreateTime.AsTime().After(defaultCreated.AsTime()), "New auth_method should have been created after default auth_method. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.AsTime().After(defaultCreated.AsTime()), "New auth_method should have been updated after default auth_method. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
				if _, ok := got.Item.Attributes.Fields["client_secret_hmac"]; ok {
					assert.NotEqual(tc.req.Item.Attributes.Fields["client_secret"], got.Item.Attributes.Fields["client_secret_hmac"])
					got.Item.Attributes.Fields["client_secret_hmac"] = structpb.NewStringValue("<hmac>")
				}
				if _, ok := got.Item.Attributes.Fields["callback_url"]; ok {
					exp := tc.res.Item.Attributes.Fields["callback_url"].GetStringValue()
					gVal := got.Item.Attributes.Fields["callback_url"].GetStringValue()
					matches, err := regexp.MatchString(exp, gVal)
					require.NoError(err)
					assert.True(matches, "%q doesn't match %q", gVal, exp)
					delete(got.Item.Attributes.Fields, "callback_url")
					delete(tc.res.Item.Attributes.Fields, "callback_url")
				}
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "CreateAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate_Password(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	tested, err := authmethods.NewService(kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}

	freshAuthMethod := func() (*pb.AuthMethod, func()) {
		am, err := tested.CreateAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
			&pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				Name:        wrapperspb.String("default"),
				Description: wrapperspb.String("default"),
				Type:        "password",
			}})
		require.NoError(t, err)

		clean := func() {
			_, err := tested.DeleteAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
				&pbs.DeleteAuthMethodRequest{Id: am.GetItem().GetId()})
			require.NoError(t, err)
		}

		return am.GetItem(), clean
	}

	cases := []struct {
		name string
		req  *pbs.UpdateAuthMethodRequest
		res  *pbs.UpdateAuthMethodResponse
		err  error
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
					Type:        "password",
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description,type"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateAuthMethodRequest{
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant change type",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"name", "type"}},
				Item: &pb.AuthMethod{
					Name: &wrapperspb.StringValue{Value: "updated name"},
					Type: "oidc",
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
					ScopeId:     o.GetPublicId(),
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
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
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
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
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
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
			err: handlers.ApiErrorWithCode(codes.NotFound),
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
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.AuthMethod{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.AuthMethod{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(8),
						"min_login_name_length": structpb.NewNumberValue(42),
					}},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
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
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
						"min_password_length":   structpb.NewNumberValue(42),
						"min_login_name_length": structpb.NewNumberValue(3),
					}},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
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

			got, gErr := tested.UpdateAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}

			if tc.res == nil {
				require.Nil(got)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateAuthMethod response to be nil, but was %v", got)

				created := am.GetCreatedTime().AsTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
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

func TestUpdate_OIDC(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	tested, err := authmethods.NewService(kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}

	tp := capoidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)
	_, _, tpAlg, _ := tp.SigningKeys()

	defaultAttributeFields := func() map[string]*structpb.Value {
		return map[string]*structpb.Value{
			"issuer":         structpb.NewStringValue(tp.Addr()),
			"client_id":      structpb.NewStringValue("someclientid"),
			"client_secret":  structpb.NewStringValue("secret"),
			"api_url_prefix": structpb.NewStringValue("http://example.com"),
			"ca_certs": func() *structpb.Value {
				lv, _ := structpb.NewList([]interface{}{tp.CACert()})
				return structpb.NewListValue(lv)
			}(),
			"signing_algorithms": func() *structpb.Value {
				lv, _ := structpb.NewList([]interface{}{string(tpAlg)})
				return structpb.NewListValue(lv)
			}(),
		}
	}
	defaultReadAttributeFields := func() map[string]*structpb.Value {
		return map[string]*structpb.Value{
			"issuer":             structpb.NewStringValue(tp.Addr()),
			"client_id":          structpb.NewStringValue("someclientid"),
			"client_secret_hmac": structpb.NewStringValue("<hmac>"),
			"state":              structpb.NewStringValue(string(oidc.ActivePrivateState)),
			"api_url_prefix":     structpb.NewStringValue("http://example.com"),
			"callback_url":       structpb.NewStringValue(fmt.Sprintf("http://example.com/v1/auth-methods/%s_[0-9A-z]*:authenticate:callback", oidc.AuthMethodPrefix)),
			"ca_certs": func() *structpb.Value {
				lv, _ := structpb.NewList([]interface{}{tp.CACert()})
				return structpb.NewListValue(lv)
			}(),
			"signing_algorithms": func() *structpb.Value {
				lv, _ := structpb.NewList([]interface{}{string(tpAlg)})
				return structpb.NewListValue(lv)
			}(),
		}
	}

	freshAuthMethod := func(t *testing.T) (*pb.AuthMethod, func()) {
		ctx := auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId())
		am, err := tested.CreateAuthMethod(ctx, &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
			ScopeId:     o.GetPublicId(),
			Name:        wrapperspb.String("default"),
			Description: wrapperspb.String("default"),
			Type:        auth.OidcSubtype.String(),
			Attributes: &structpb.Struct{
				Fields: defaultAttributeFields(),
			},
		}})
		require.NoError(t, err)

		csr, err := tested.ChangeState(ctx, &pbs.ChangeStateRequest{
			Id:      am.GetItem().GetId(),
			Version: am.GetItem().GetVersion(),
			Attributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{"state": structpb.NewStringValue("active-private")},
			},
		})
		require.NoError(t, err)

		clean := func() {
			_, err := tested.DeleteAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
				&pbs.DeleteAuthMethodRequest{Id: am.GetItem().GetId()})
			require.NoError(t, err)
		}
		return csr.GetItem(), clean
	}

	cases := []struct {
		name    string
		req     *pbs.UpdateAuthMethodRequest
		res     *pbs.UpdateAuthMethodResponse
		err     error
		wantErr bool
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
					Type:        auth.OidcSubtype.String(),
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: defaultReadAttributeFields(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description,type"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        auth.OidcSubtype.String(),
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: defaultReadAttributeFields(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateAuthMethodRequest{
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant change type",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"name", "type"}},
				Item: &pb.AuthMethod{
					Name: &wrapperspb.StringValue{Value: "updated name"},
					Type: auth.PasswordSubtype.String(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
					ScopeId:     o.GetPublicId(),
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: defaultReadAttributeFields(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.AuthMethod{
					Name: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId: o.GetPublicId(),
					Name:    &wrapperspb.StringValue{Value: "default"},
					Type:    auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: defaultReadAttributeFields(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
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
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: defaultReadAttributeFields(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
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
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: defaultReadAttributeFields(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
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
			err: handlers.ApiErrorWithCode(codes.NotFound),
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
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.AuthMethod{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.AuthMethod{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Type",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"type"},
				},
				Item: &pb.AuthMethod{
					Type: auth.OidcSubtype.String(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Client Id",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.client_id"},
				},
				Item: &pb.AuthMethod{},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Client Secret",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.client_secret"},
				},
				Item: &pb.AuthMethod{},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Signing Algorithms",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.signing_algorithms"},
				},
				Item: &pb.AuthMethod{},
			},
			wantErr: true,
		},
		{
			name: "Set Max Age to zero",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.max_age"},
				},
				Item: &pb.AuthMethod{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"max_age": structpb.NewNumberValue(0),
						},
					},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Change Max Age",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.max_age"},
				},
				Item: &pb.AuthMethod{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"max_age": structpb.NewNumberValue(4),
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: func() map[string]*structpb.Value {
							f := defaultReadAttributeFields()
							f["max_age"] = structpb.NewNumberValue(4)
							return f
						}(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Change Client Id",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.client_id"},
				},
				Item: &pb.AuthMethod{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"client_id": structpb.NewStringValue("new id"),
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: func() map[string]*structpb.Value {
							f := defaultReadAttributeFields()
							f["client_id"] = structpb.NewStringValue("new id")
							return f
						}(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Change Api Url Prefix",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.api_url_prefix"},
				},
				Item: &pb.AuthMethod{
					Attributes: &structpb.Struct{
						Fields: func() map[string]*structpb.Value {
							f := map[string]*structpb.Value{
								"api_url_prefix": structpb.NewStringValue("https://callback.prefix:9281/path"),
							}
							return f
						}(),
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: func() map[string]*structpb.Value {
							f := defaultReadAttributeFields()
							f["api_url_prefix"] = structpb.NewStringValue("https://callback.prefix:9281/path")
							f["callback_url"] = structpb.NewStringValue(fmt.Sprintf("https://callback.prefix:9281/path/v1/auth-methods/%s_[0-9A-z]*:authenticate:callback", oidc.AuthMethodPrefix))
							return f
						}(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Change Allowed Audiences",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.allowed_audiences"},
				},
				Item: &pb.AuthMethod{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"allowed_audiences": func() *structpb.Value {
								lv, _ := structpb.NewList([]interface{}{"bar", "foo"})
								return structpb.NewListValue(lv)
							}(),
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: func() map[string]*structpb.Value {
							f := defaultReadAttributeFields()
							f["allowed_audiences"] = func() *structpb.Value {
								lv, _ := structpb.NewList([]interface{}{"bar", "foo"})
								return structpb.NewListValue(lv)
							}()
							return f
						}(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Unset Issuer Is Incomplete",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.issuer"},
				},
				Item: &pb.AuthMethod{},
			},
			wantErr: true,
		},
		{
			name: "Unsupported Signing Algorithms",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.signing_algorithms"},
				},
				Item: &pb.AuthMethod{
					Attributes: &structpb.Struct{
						Fields: func() map[string]*structpb.Value {
							f := defaultAttributeFields()
							f["signing_algorithms"] = func() *structpb.Value {
								lv, _ := structpb.NewList([]interface{}{string(oidc.EdDSA)})
								return structpb.NewListValue(lv)
							}()
							return f
						}(),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Forced Unsupported Signing Algorithms",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.signing_algorithms"},
				},
				Item: &pb.AuthMethod{
					Attributes: &structpb.Struct{
						Fields: func() map[string]*structpb.Value {
							f := defaultAttributeFields()
							f["disable_discovered_config_validation"] = structpb.NewBoolValue(true)
							f["signing_algorithms"] = func() *structpb.Value {
								lv, _ := structpb.NewList([]interface{}{string(oidc.EdDSA)})
								return structpb.NewListValue(lv)
							}()
							return f
						}(),
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        auth.OidcSubtype.String(),
					Attributes: &structpb.Struct{
						Fields: func() map[string]*structpb.Value {
							f := defaultReadAttributeFields()
							f["signing_algorithms"] = func() *structpb.Value {
								lv, _ := structpb.NewList([]interface{}{string(oidc.EdDSA)})
								return structpb.NewListValue(lv)
							}()
							return f
						}(),
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			am, cleanup := freshAuthMethod(t)
			defer cleanup()

			tc.req.Item.Version = am.GetVersion()

			if tc.req.GetId() == "" {
				tc.req.Id = am.GetId()
			}

			if tc.res != nil && tc.res.Item != nil {
				tc.res.Item.Id = am.GetId()
				tc.res.Item.CreatedTime = am.GetCreatedTime()
			}

			got, gErr := tested.UpdateAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			// TODO: When handlers move to domain errors remove wantErr and rely errors.Match here.
			if tc.err != nil || tc.wantErr {
				require.Error(gErr)
				if tc.err != nil {
					assert.True(errors.Is(gErr, tc.err), "UpdateAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				}
				return
			}
			require.NoError(gErr)
			if tc.res == nil {
				require.Nil(got)
			}

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateAuthMethod response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				created := am.GetCreatedTime().AsTime()

				// Verify it is a auth_method updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated auth_method should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Clear all values which are hard to compare against.
				if _, ok := got.Item.Attributes.Fields["client_secret_hmac"]; ok {
					assert.NotEqual("secret", got.Item.Attributes.Fields["client_secret_hmac"])
					got.Item.Attributes.Fields["client_secret_hmac"] = structpb.NewStringValue("<hmac>")
				}
				if _, ok := got.Item.Attributes.Fields["callback_url"]; ok {
					exp := tc.res.Item.Attributes.Fields["callback_url"].GetStringValue()
					gVal := got.Item.Attributes.Fields["callback_url"].GetStringValue()
					matches, err := regexp.MatchString(exp, gVal)
					require.NoError(err)
					assert.True(matches, "%q doesn't match %q", gVal, exp)
					delete(got.Item.Attributes.Fields, "callback_url")
					delete(tc.res.Item.Attributes.Fields, "callback_url")
				}

				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

				assert.EqualValues(3, got.Item.Version)
				tc.res.Item.Version = 3
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.SortRepeatedFields(got)), "UpdateAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestChangeState(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kmsCache)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	pwam := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	tp := capoidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)
	_, _, tpAlg, _ := tp.SigningKeys()
	tpCert, err := oidc.ParseCertificates(tp.CACert())

	incompleteAm := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, "inactive", oidc.TestConvertToUrls(t, "https://alice.com")[0], "client id", "secret")
	oidcam := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, "inactive", oidc.TestConvertToUrls(t, tp.Addr())[0], tpClientId, oidc.ClientSecret(tpClientSecret),
		oidc.WithSigningAlgs(oidc.Alg(tpAlg)), oidc.WithCallbackUrls(oidc.TestConvertToUrls(t, "https://example.callback:58")[0]), oidc.WithCertificates(tpCert...))
	mismatchedAM := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, "inactive", oidc.TestConvertToUrls(t, tp.Addr())[0], "different_client_id", oidc.ClientSecret(tpClientSecret),
		oidc.WithSigningAlgs(oidc.EdDSA), oidc.WithCallbackUrls(oidc.TestConvertToUrls(t, "https://example.callback:58")[0]), oidc.WithCertificates(tpCert...))

	s, err := authmethods.NewService(kmsCache, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	signingAlg := func() *structpb.Value {
		lv, err := structpb.NewList([]interface{}{string(tpAlg)})
		require.NoError(t, err)
		return structpb.NewListValue(lv)
	}()

	certs := func() *structpb.Value {
		lv, err := structpb.NewList([]interface{}{tp.CACert()})
		require.NoError(t, err)
		return structpb.NewListValue(lv)
	}()

	wantTemplate := &pb.AuthMethod{
		Id:          oidcam.GetPublicId(),
		ScopeId:     oidcam.GetScopeId(),
		CreatedTime: oidcam.CreateTime.GetTimestamp(),
		UpdatedTime: oidcam.UpdateTime.GetTimestamp(),
		Type:        auth.OidcSubtype.String(),
		Attributes: &structpb.Struct{Fields: map[string]*structpb.Value{
			"issuer":             structpb.NewStringValue(oidcam.DiscoveryUrl),
			"client_id":          structpb.NewStringValue(tpClientId),
			"client_secret_hmac": structpb.NewStringValue("<hmac>"),
			"state":              structpb.NewStringValue(string(oidc.InactiveState)),
			"callback_url":       structpb.NewStringValue("https://example.callback:58/v1/auth-methods/amoidc_[0-9A-z]*:authenticate:callback"),
			"api_url_prefix":     structpb.NewStringValue("https://example.callback:58"),
			"signing_algorithms": signingAlg,
			"ca_certs":           certs,
		}},
		Version: 1,
		Scope: &scopepb.ScopeInfo{
			Id:            o.GetPublicId(),
			Type:          o.GetType(),
			ParentScopeId: scope.Global.String(),
		},
		AuthorizedActions:           oidcAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
	}

	toState := func(s string) *structpb.Struct {
		return &structpb.Struct{Fields: map[string]*structpb.Value{"state": structpb.NewStringValue(s)}}
	}

	// These test cases must be run in this order since these tests rely on the correct versions being provided
	cases := []struct {
		name string
		req  *pbs.ChangeStateRequest
		res  *pbs.ChangeStateResponse
		err  bool
	}{
		{
			name: "Password Auth Method",
			req:  &pbs.ChangeStateRequest{Id: pwam.GetPublicId(), Version: pwam.GetVersion(), Attributes: toState("inactive")},
			err:  true,
		},
		{
			name: "No Version Specified",
			req:  &pbs.ChangeStateRequest{Id: oidcam.GetPublicId(), Attributes: toState("inactive")},
			err:  true,
		},
		{
			name: "Keep Inactive",
			req:  &pbs.ChangeStateRequest{Id: oidcam.GetPublicId(), Version: oidcam.GetVersion(), Attributes: toState("inactive")},
			res: &pbs.ChangeStateResponse{Item: func() *pb.AuthMethod {
				am := proto.Clone(wantTemplate).(*pb.AuthMethod)
				return am
			}()},
		},
		{
			name: "Make Incomplete Private",
			req:  &pbs.ChangeStateRequest{Id: incompleteAm.GetPublicId(), Version: oidcam.GetVersion(), Attributes: toState("active-private")},
			err:  true,
		},
		{
			name: "Make Incomplete Public",
			req:  &pbs.ChangeStateRequest{Id: incompleteAm.GetPublicId(), Version: oidcam.GetVersion(), Attributes: toState("active-public")},
			err:  true,
		},
		{
			name: "Mismatched To Public",
			req: &pbs.ChangeStateRequest{
				Id:         mismatchedAM.GetPublicId(),
				Version:    mismatchedAM.GetVersion(),
				Attributes: toState("active-public"),
			},
			err: true,
		},
		{
			name: "Force Mismatched To Public",
			req: &pbs.ChangeStateRequest{
				Id:      mismatchedAM.GetPublicId(),
				Version: mismatchedAM.GetVersion(),
				Attributes: func() *structpb.Struct {
					s := toState("active-public")
					s.Fields["override_oidc_discovery_url_config"] = structpb.NewBoolValue(true)
					return s
				}(),
			},
			res: &pbs.ChangeStateResponse{Item: func() *pb.AuthMethod {
				am := proto.Clone(wantTemplate).(*pb.AuthMethod)
				am.Id = mismatchedAM.PublicId
				am.Attributes.Fields["state"] = structpb.NewStringValue("active-public")
				am.Attributes.Fields["client_id"] = structpb.NewStringValue(mismatchedAM.ClientId)
				am.Attributes.Fields["signing_algorithms"] = func() *structpb.Value {
					lv, _ := structpb.NewList([]interface{}{string(oidc.EdDSA)})
					return structpb.NewListValue(lv)
				}()
				am.CreatedTime = mismatchedAM.CreateTime.GetTimestamp()
				am.Version = 2
				return am
			}()},
		},
		{
			name: "Make Complete Private",
			req:  &pbs.ChangeStateRequest{Id: oidcam.GetPublicId(), Version: oidcam.GetVersion(), Attributes: toState("active-private")},
			res: &pbs.ChangeStateResponse{Item: func() *pb.AuthMethod {
				am := proto.Clone(wantTemplate).(*pb.AuthMethod)
				am.Attributes.Fields["state"] = structpb.NewStringValue("active-private")
				am.Version = 2
				return am
			}()},
		},
		{
			name: "Make Complete Public",
			req:  &pbs.ChangeStateRequest{Id: oidcam.GetPublicId(), Version: 2, Attributes: toState("active-public")},
			res: &pbs.ChangeStateResponse{Item: func() *pb.AuthMethod {
				am := proto.Clone(wantTemplate).(*pb.AuthMethod)
				am.Attributes.Fields["state"] = structpb.NewStringValue("active-public")
				am.Version = 3
				return am
			}()},
		},
		{
			name: "Make Complete Inactive",
			req:  &pbs.ChangeStateRequest{Id: oidcam.GetPublicId(), Version: 3, Attributes: toState("inactive")},
			res: &pbs.ChangeStateResponse{Item: func() *pb.AuthMethod {
				am := proto.Clone(wantTemplate).(*pb.AuthMethod)
				am.Attributes.Fields["state"] = structpb.NewStringValue("inactive")
				am.Version = 4
				return am
			}()},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, gErr := s.ChangeState(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err {
				require.Error(gErr)
				return
			}
			require.NoError(gErr)
			if _, ok := got.Item.Attributes.Fields["client_secret_hmac"]; ok {
				got.Item.Attributes.Fields["client_secret_hmac"] = structpb.NewStringValue("<hmac>")
			}
			if _, ok := got.Item.Attributes.Fields["callback_url"]; ok {
				exp := tc.res.Item.Attributes.Fields["callback_url"].GetStringValue()
				gVal := got.Item.Attributes.Fields["callback_url"].GetStringValue()
				matches, err := regexp.MatchString(exp, gVal)
				require.NoError(err)
				assert.True(matches, "%q doesn't match %q", gVal, exp)
				delete(got.Item.Attributes.Fields, "callback_url")
				delete(tc.res.Item.Attributes.Fields, "callback_url")
			}
			got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "ChangeState() got response %q, wanted %q", got, tc.res)
		})
	}
}

func TestAuthenticate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	iam.TestSetPrimaryAuthMethod(t, iam.TestRepo(t, conn, wrapper), o, am.PublicId)

	acct, err := password.NewAccount(am.GetPublicId(), password.WithLoginName(testLoginName))
	require.NoError(t, err)

	pwRepo, err := pwRepoFn()
	require.NoError(t, err)
	acct, err = pwRepo.CreateAccount(context.Background(), o.GetPublicId(), acct, password.WithPassword(testPassword))
	require.NoError(t, err)
	require.NotNil(t, acct)

	cases := []struct {
		name     string
		request  *pbs.AuthenticateRequest
		wantType string
		wantErr  error
	}{
		{
			name: "basic",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantType: "token",
		},
		{
			name: "cookie-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "cookie",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantType: "cookie",
		},
		{
			name: "no-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
		},
		{
			name: "bad-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "email",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "no-authmethod",
			request: &pbs.AuthenticateRequest{
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "wrong-password",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: "wrong"}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.Unauthenticated),
		},
		{
			name: "wrong-login-name",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: "wrong"}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.Unauthenticated),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := authmethods.NewService(kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
			require.NoError(err)

			resp, err := s.Authenticate(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.request)
			if tc.wantErr != nil {
				assert.Error(err)
				assert.Truef(errors.Is(err, tc.wantErr), "Got %#v, wanted %#v", err, tc.wantErr)
				return
			}
			require.NoError(err)
			aToken := resp.GetItem()
			assert.NotEmpty(aToken.GetId())
			assert.NotEmpty(aToken.GetToken())
			assert.True(strings.HasPrefix(aToken.GetToken(), aToken.GetId()))
			assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetUpdatedTime())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetApproximateLastUsedTime())
			assert.Equal(acct.GetPublicId(), aToken.GetAccountId())
			assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
			assert.Equal(tc.wantType, resp.GetTokenType())
		})
	}
}

func TestAuthenticateLogin(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	iam.TestSetPrimaryAuthMethod(t, iam.TestRepo(t, conn, wrapper), o, am.PublicId)

	acct, err := password.NewAccount(am.GetPublicId(), password.WithLoginName(testLoginName))
	require.NoError(t, err)

	pwRepo, err := pwRepoFn()
	require.NoError(t, err)
	acct, err = pwRepo.CreateAccount(context.Background(), o.GetPublicId(), acct, password.WithPassword(testPassword))
	require.NoError(t, err)
	require.NotNil(t, acct)

	cases := []struct {
		name     string
		request  *pbs.AuthenticateLoginRequest
		wantType string
		wantErr  error
	}{
		{
			name: "basic",
			request: &pbs.AuthenticateLoginRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantType: "token",
		},
		{
			name: "cookie-type",
			request: &pbs.AuthenticateLoginRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "cookie",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantType: "cookie",
		},
		{
			name: "no-token-type",
			request: &pbs.AuthenticateLoginRequest{
				AuthMethodId: am.GetPublicId(),
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
		},
		{
			name: "bad-token-type",
			request: &pbs.AuthenticateLoginRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "email",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "no-authmethod",
			request: &pbs.AuthenticateLoginRequest{
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "wrong-password",
			request: &pbs.AuthenticateLoginRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: "wrong"}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.Unauthenticated),
		},
		{
			name: "wrong-login-name",
			request: &pbs.AuthenticateLoginRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Credentials: func() *structpb.Struct {
					creds := map[string]*structpb.Value{
						"login_name": {Kind: &structpb.Value_StringValue{StringValue: "wrong"}},
						"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
					}
					return &structpb.Struct{Fields: creds}
				}(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.Unauthenticated),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := authmethods.NewService(kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
			require.NoError(err)

			resp, err := s.AuthenticateLogin(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.request)
			if tc.wantErr != nil {
				assert.Error(err)
				assert.Truef(errors.Is(err, tc.wantErr), "Got %#v, wanted %#v", err, tc.wantErr)
				return
			}
			require.NoError(err)
			aToken := resp.GetItem()
			assert.NotEmpty(aToken.GetId())
			assert.NotEmpty(aToken.GetToken())
			assert.True(strings.HasPrefix(aToken.GetToken(), aToken.GetId()))
			assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetUpdatedTime())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetApproximateLastUsedTime())
			assert.Equal(acct.GetPublicId(), aToken.GetAccountId())
			assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
			assert.Equal(tc.wantType, resp.GetTokenType())
		})
	}
}

func TestAuthenticate_AuthAccountConnectedToIamUser(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}

	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	acct, err := password.NewAccount(am.GetPublicId(), password.WithLoginName(testLoginName))
	require.NoError(err)

	pwRepo, err := pwRepoFn()
	require.NoError(err)
	acct, err = pwRepo.CreateAccount(context.Background(), o.GetPublicId(), acct, password.WithPassword(testPassword))
	require.NoError(err)

	// connected to an account.
	iamRepo, err := iamRepoFn()
	require.NoError(err)
	iam.TestUser(t, iamRepo, am.ScopeId, iam.WithAccountIds(acct.PublicId))
	iamUser, err := iamRepo.LookupUserWithLogin(context.Background(), acct.GetPublicId())
	require.NoError(err)

	s, err := authmethods.NewService(kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
	require.NoError(err)
	resp, err := s.Authenticate(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), &pbs.AuthenticateRequest{
		AuthMethodId: am.GetPublicId(),
		Credentials: func() *structpb.Struct {
			creds := map[string]*structpb.Value{
				"login_name": {Kind: &structpb.Value_StringValue{StringValue: testLoginName}},
				"password":   {Kind: &structpb.Value_StringValue{StringValue: testPassword}},
			}
			return &structpb.Struct{Fields: creds}
		}(),
	})
	require.NoError(err)

	aToken := resp.GetItem()
	assert.Equal(iamUser.GetPublicId(), aToken.GetUserId())
	assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
	assert.Equal(acct.GetPublicId(), aToken.GetAccountId())

	assert.NotEmpty(aToken.GetId())
	assert.NotEmpty(aToken.GetToken())
	assert.True(strings.HasPrefix(aToken.GetToken(), aToken.GetId()))
}
