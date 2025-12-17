// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethods_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"

	am "github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	capoidc "github.com/hashicorp/cap/oidc"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type setup struct {
	ctx                         context.Context
	conn                        *db.DB
	rw                          *db.Db
	rootWrapper                 wrapping.Wrapper
	kmsCache                    *kms.Kms
	iamRepo                     *iam.Repository
	iamRepoFn                   common.IamRepoFactory
	oidcRepoFn                  common.OidcAuthRepoFactory
	ldapRepoFn                  common.LdapAuthRepoFactory
	pwRepoFn                    common.PasswordAuthRepoFactory
	atRepoFn                    common.AuthTokenRepoFactory
	authMethodRepoFn            common.AuthMethodRepoFactory
	maxPageSize                 int
	org                         *iam.Scope
	proj                        *iam.Scope
	databaseWrapper             wrapping.Wrapper
	authMethodService           authmethods.Service
	testProvider                *capoidc.TestProvider
	testProviderAlg             capoidc.Alg
	testProviderCaCert          []*x509.Certificate
	testController              *httptest.Server
	authMethod                  *oidc.AuthMethod
	testProviderAllowedRedirect string
}

func getSetup(t *testing.T) setup {
	t.Helper()
	ctx := context.TODO()
	require := require.New(t)
	var ret setup
	var err error
	ret.ctx = context.Background()

	ret.conn, _ = db.TestSetup(t, "postgres")
	ret.rw = db.New(ret.conn)
	ret.rootWrapper = db.TestWrapper(t)
	ret.kmsCache = kms.TestKms(t, ret.conn, ret.rootWrapper)

	ret.iamRepo = iam.TestRepo(t, ret.conn, ret.rootWrapper)
	ret.iamRepoFn = func() (*iam.Repository, error) {
		return ret.iamRepo, nil
	}
	ret.oidcRepoFn = func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, ret.rw, ret.rw, ret.kmsCache)
	}
	ret.ldapRepoFn = func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, ret.rw, ret.rw, ret.kmsCache)
	}
	ret.pwRepoFn = func() (*password.Repository, error) {
		return password.NewRepository(ctx, ret.rw, ret.rw, ret.kmsCache)
	}
	ret.atRepoFn = func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, ret.rw, ret.rw, ret.kmsCache)
	}
	ret.authMethodRepoFn = func() (*am.AuthMethodRepository, error) {
		return am.NewAuthMethodRepository(ctx, ret.rw, ret.rw, ret.kmsCache)
	}
	ret.maxPageSize = 1000

	ret.org, ret.proj = iam.TestScopes(t, ret.iamRepo)
	ret.databaseWrapper, err = ret.kmsCache.GetWrapper(ret.ctx, ret.org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(err)

	ret.authMethodService, err = authmethods.NewService(
		ret.ctx,
		ret.kmsCache,
		ret.pwRepoFn,
		ret.oidcRepoFn,
		ret.iamRepoFn,
		ret.atRepoFn,
		ret.ldapRepoFn,
		ret.authMethodRepoFn,
		uint(ret.maxPageSize),
	)
	require.NoError(err)

	ret.testProvider = capoidc.StartTestProvider(t)
	_, _, ret.testProviderAlg, _ = ret.testProvider.SigningKeys()
	ret.testProviderCaCert, err = oidc.ParseCertificates(ctx, ret.testProvider.CACert())
	require.NoError(err)

	ret.testController = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(ret.testController.Close)

	ret.authMethod = oidc.TestAuthMethod(
		t, ret.conn, ret.databaseWrapper, ret.org.PublicId, oidc.ActivePublicState,
		"test-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, ret.testProvider.Addr())[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, ret.testController.URL)[0]),
		oidc.WithSigningAlgs(oidc.Alg(ret.testProviderAlg)),
		oidc.WithCertificates(ret.testProviderCaCert...),
		oidc.WithPrompts(oidc.Consent),
	)

	ret.testProviderAllowedRedirect = fmt.Sprintf(oidc.CallbackEndpoint, ret.testController.URL)
	ret.testProvider.SetAllowedRedirectURIs([]string{ret.testProviderAllowedRedirect})

	r, err := ret.oidcRepoFn()
	require.NoError(err)
	// update the test's auth method, now that we've added a new callback
	ret.authMethod, err = r.LookupAuthMethod(ret.ctx, ret.authMethod.PublicId)
	require.NoError(err)
	require.NotNil(ret.authMethod)
	return ret
}

func TestList_FilterNonPublic(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kmsCache)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}
	authMethodRepoFn := func() (*am.AuthMethodRepository, error) {
		return am.NewAuthMethodRepository(ctx, rw, rw, kmsCache)
	}

	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, o.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)

	// 1 Public
	i := 0
	oidcam := oidc.TestAuthMethod(t, conn, databaseWrapper, o.GetPublicId(), oidc.ActivePublicState, "alice_rp", "secret", oidc.WithDescription(fmt.Sprintf("%d", i)),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, fmt.Sprintf("https://alice%d.com", i))[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]), oidc.WithSigningAlgs(oidc.EdDSA))
	i++
	iam.TestSetPrimaryAuthMethod(t, iamRepo, o, oidcam.GetPublicId())

	// 4 private
	for ; i < 4; i++ {
		_ = oidc.TestAuthMethod(t, conn, databaseWrapper, o.GetPublicId(), oidc.ActivePrivateState, "alice_rp", "secret", oidc.WithDescription(fmt.Sprintf("%d", i)),
			oidc.WithIssuer(oidc.TestConvertToUrls(t, fmt.Sprintf("https://alice%d.com", i))[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]), oidc.WithSigningAlgs(oidc.EdDSA))
	}

	// 5 inactive
	for ; i < 10; i++ {
		_ = oidc.TestAuthMethod(t, conn, databaseWrapper, o.GetPublicId(), oidc.InactiveState, "alice_rp", "secret", oidc.WithDescription(fmt.Sprintf("%d", i)),
			oidc.WithIssuer(oidc.TestConvertToUrls(t, fmt.Sprintf("https://alice%d.com", i))[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]))
	}

	s, err := authmethods.NewService(ctx, kmsCache, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn, ldapRepoFn, authMethodRepoFn, 1000)
	require.NoError(t, err, "Couldn't create new auth_method service.")

	req := &pbs.ListAuthMethodsRequest{
		ScopeId: o.GetPublicId(),
		Filter:  `"/item/type"=="oidc"`, // We are concerned about OIDC auth methods being filtered by authn state
	}

	cases := []struct {
		name      string
		reqCtx    context.Context
		respCount int
	}{
		{
			name:      "unauthenticated",
			reqCtx:    auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)),
			respCount: 1,
		},
		{
			name: "authenticated",
			reqCtx: func() context.Context {
				at := authtoken.TestAuthToken(t, conn, kmsCache, o.GetPublicId())
				return auth.NewVerifierContext(requests.NewRequestContext(context.Background()),
					iamRepoFn,
					atRepoFn,
					serversRepoFn,
					kmsCache,
					&authpb.RequestInfo{
						Token:       at.GetToken(),
						TokenFormat: uint32(auth.AuthTokenTypeBearer),
						PublicId:    at.GetPublicId(),
					})
			}(),
			respCount: 10,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.ListAuthMethods(tc.reqCtx, req)
			assert.NoError(t, err)
			require.NotNil(t, got)
			require.Len(t, got.GetItems(), tc.respCount)

			gotSorted := got.GetItems()
			sort.Slice(gotSorted, func(i, j int) bool {
				return gotSorted[i].GetDescription().GetValue() < gotSorted[j].GetDescription().GetValue()
			})
			for i := 0; i < tc.respCount; i++ {
				assert.Equal(t, fmt.Sprintf("%d", i), gotSorted[i].GetDescription().GetValue(), "Auth method with description '%d' missing", i)
			}
		})
	}
}

func TestUpdate_OIDC(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	authMethodRepoFn := func() (*am.AuthMethodRepository, error) {
		return am.NewAuthMethodRepository(ctx, rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	tested, err := authmethods.NewService(ctx, kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn, ldapRepoFn, authMethodRepoFn, 1000)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}

	tp := capoidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)
	_, _, tpAlg, _ := tp.SigningKeys()
	tpPrompt := capoidc.None

	defaultAttributes := &pb.AuthMethod_OidcAuthMethodsAttributes{
		OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
			Issuer:            wrapperspb.String(tp.Addr()),
			ClientId:          wrapperspb.String("someclientid"),
			ClientSecret:      wrapperspb.String("secret"),
			ApiUrlPrefix:      wrapperspb.String("https://example.com"),
			IdpCaCerts:        []string{tp.CACert()},
			SigningAlgorithms: []string{string(tpAlg)},
			Prompts:           []string{string(tpPrompt)},
		},
	}
	defaultReadAttributes := &pb.AuthMethod_OidcAuthMethodsAttributes{
		OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
			Issuer:            wrapperspb.String(tp.Addr()),
			ClientId:          wrapperspb.String("someclientid"),
			ClientSecretHmac:  "<hmac>",
			State:             string(oidc.ActivePrivateState),
			ApiUrlPrefix:      wrapperspb.String("https://example.com"),
			CallbackUrl:       "https://example.com/v1/auth-methods/oidc:authenticate:callback",
			IdpCaCerts:        []string{tp.CACert()},
			SigningAlgorithms: []string{string(tpAlg)},
			Prompts:           []string{string(tpPrompt)},
		},
	}

	freshAuthMethod := func(t *testing.T) (*pb.AuthMethod, func()) {
		ctx := auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId())
		am, err := tested.CreateAuthMethod(ctx, &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
			ScopeId:     o.GetPublicId(),
			Name:        wrapperspb.String("default"),
			Description: wrapperspb.String("default"),
			Type:        oidc.Subtype.String(),
			Attrs:       defaultAttributes,
		}})
		require.NoError(t, err)

		csr, err := tested.ChangeState(ctx, &pbs.ChangeStateRequest{
			Id:      am.GetItem().GetId(),
			Version: am.GetItem().GetVersion(),
			Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
				OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
					State: "active-private",
				},
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
					Type:        oidc.Subtype.String(),
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:                     o.GetPublicId(),
					Name:                        &wrapperspb.StringValue{Value: "new"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					Type:                        oidc.Subtype.String(),
					Attrs:                       defaultReadAttributes,
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
					Type:        oidc.Subtype.String(),
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:                     o.GetPublicId(),
					Name:                        &wrapperspb.StringValue{Value: "new"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					Type:                        oidc.Subtype.String(),
					Attrs:                       defaultReadAttributes,
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Update Issuer",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.issuer"},
				},
				Item: &pb.AuthMethod{
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.Issuer = wrapperspb.String("http://localhost:72759/somepath/.well-known/openid-configuration")
						f.DisableDiscoveredConfigValidation = true
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.Issuer = wrapperspb.String("http://localhost:72759/somepath/")
						f.DisableDiscoveredConfigValidation = true
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),

					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Update Issuer IPv6",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.issuer"},
				},
				Item: &pb.AuthMethod{
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.Issuer = wrapperspb.String("https://[2001:BEEF:0000:0000:0000:0000:0000:0001]:44344/v1/myissuer/.well-known/openid-configuration")
						f.DisableDiscoveredConfigValidation = true
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.Issuer = wrapperspb.String("https://[2001:beef::1]:44344/v1/myissuer/")
						f.DisableDiscoveredConfigValidation = true
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),

					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "invalid-issuer-port",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.issuer"},
				},
				Item: &pb.AuthMethod{
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.Issuer = wrapperspb.String("http://localhost:7dddd")
						f.DisableDiscoveredConfigValidation = true
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
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
			name: "Only non-existent paths in Mask",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
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
					Type: password.Subtype.String(),
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant change is primary",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"is_primary"}},
				Item: &pb.AuthMethod{
					IsPrimary: true,
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
					ScopeId:                     o.GetPublicId(),
					Description:                 &wrapperspb.StringValue{Value: "default"},
					Type:                        oidc.Subtype.String(),
					Attrs:                       defaultReadAttributes,
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
					ScopeId:                     o.GetPublicId(),
					Name:                        &wrapperspb.StringValue{Value: "default"},
					Type:                        oidc.Subtype.String(),
					Attrs:                       defaultReadAttributes,
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
					ScopeId:                     o.GetPublicId(),
					Name:                        &wrapperspb.StringValue{Value: "updated"},
					Description:                 &wrapperspb.StringValue{Value: "default"},
					Type:                        oidc.Subtype.String(),
					Attrs:                       defaultReadAttributes,
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
					ScopeId:                     o.GetPublicId(),
					Name:                        &wrapperspb.StringValue{Value: "default"},
					Description:                 &wrapperspb.StringValue{Value: "notignored"},
					Type:                        oidc.Subtype.String(),
					Attrs:                       defaultReadAttributes,
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Update a Non Existing AuthMethod",
			req: &pbs.UpdateAuthMethodRequest{
				Id: globals.PasswordAuthMethodPrefix + "_DoesntExis",
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
					Id:          globals.PasswordAuthMethodPrefix + "_somethinge",
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
					Type: oidc.Subtype.String(),
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
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							MaxAge: wrapperspb.UInt32(0),
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.MaxAge = wrapperspb.UInt32(0)
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Change Max Age",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.max_age"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							MaxAge: wrapperspb.UInt32(4),
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.MaxAge = wrapperspb.UInt32(4)
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
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
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							ClientId: wrapperspb.String("new id"),
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.ClientId = wrapperspb.String("new id")
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Unset Api Url Prefix",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.api_url_prefix"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							ApiUrlPrefix: nil, // Not strictly necessary to populate this, since it is the zero value, but be explicit
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Change Api Url Prefix",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.api_url_prefix"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							ApiUrlPrefix: wrapperspb.String("https://callback.prefix:9281/path"),
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.ApiUrlPrefix = wrapperspb.String("https://callback.prefix:9281/path")
						f.CallbackUrl = "https://callback.prefix:9281/path/v1/auth-methods/oidc:authenticate:callback"
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Change Api Url Prefix IPv6",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.api_url_prefix"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							ApiUrlPrefix: wrapperspb.String("https://[2001:BEEF:0000:0000:0000:0000:0000:0001]:44344/path"),
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.ApiUrlPrefix = wrapperspb.String("https://[2001:beef::1]:44344/path")
						f.CallbackUrl = "https://[2001:beef::1]:44344/path/v1/auth-methods/oidc:authenticate:callback"
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
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
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							AllowedAudiences: []string{"bar", "foo"},
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.AllowedAudiences = []string{"bar", "foo"}
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Change Claims Scopes",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.claims_scopes"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							ClaimsScopes: []string{"email", "profile"},
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.ClaimsScopes = []string{"email", "profile"}
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Change Account Claim Maps",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.account_claim_maps"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							AccountClaimMaps: []string{"display_name=name"},
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.AccountClaimMaps = []string{"display_name=name"}
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Attempt to Change Account Claim Maps for sub",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.account_claim_maps"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							AccountClaimMaps: []string{"oid=sub"},
						},
					},
				},
			},
			wantErr: true,
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
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							SigningAlgorithms: []string{string(oidc.EdDSA)},
						},
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
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							DisableDiscoveredConfigValidation: true,
							SigningAlgorithms:                 []string{string(oidc.EdDSA)},
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.SigningAlgorithms = []string{string(oidc.EdDSA)}
						f.DisableDiscoveredConfigValidation = true
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Unsupported Prompts",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.prompts"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							Prompts: []string{string("invalid")},
						},
					},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Update Prompt With Valid Values",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.prompts"},
				},
				Item: &pb.AuthMethod{
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							Prompts: []string{string(oidc.Consent), string(oidc.SelectAccount)},
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        oidc.Subtype.String(),
					Attrs: func() *pb.AuthMethod_OidcAuthMethodsAttributes {
						f := proto.Clone(defaultReadAttributes.OidcAuthMethodsAttributes).(*pb.OidcAuthMethodAttributes)
						f.Prompts = []string{string(oidc.Consent), string(oidc.SelectAccount)}
						return &pb.AuthMethod_OidcAuthMethodsAttributes{OidcAuthMethodsAttributes: f}
					}(),
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
			cmpOptions := []cmp.Option{
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			}
			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateAuthMethod response to be nil, but was %v", got)
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				created := am.GetCreatedTime().AsTime()

				// Verify it is a auth_method updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated auth_method should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Ignore all values which are hard to compare against.
				cmpOptions = append(
					cmpOptions,
					protocmp.IgnoreFields(&pb.AuthMethod{}, "updated_time"),
					protocmp.IgnoreFields(&pb.OidcAuthMethodAttributes{}, "client_secret_hmac", "callback_url"),
				)
				assert.NotEqual("secret", got.Item.GetOidcAuthMethodsAttributes().GetClientSecretHmac())
				if got.Item.GetOidcAuthMethodsAttributes().CallbackUrl != "" {
					exp := tc.res.Item.GetOidcAuthMethodsAttributes().GetCallbackUrl()
					gVal := got.Item.GetOidcAuthMethodsAttributes().GetCallbackUrl()
					assert.Equal(exp, gVal, "%q doesn't match %q", exp, gVal)
				}

				assert.EqualValues(3, got.Item.Version)
				tc.res.Item.Version = 3

			}
			assert.Empty(cmp.Diff(got, tc.res, cmpOptions...), "UpdateAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestUpdate_OIDCDryRun(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kmsCache)
	}
	authMethodRepoFn := func() (*am.AuthMethodRepository, error) {
		return am.NewAuthMethodRepository(ctx, rw, rw, kmsCache)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)

	tp := capoidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)
	_, _, tpAlg, _ := tp.SigningKeys()

	tpCert, err := oidc.ParseCertificates(ctx, tp.CACert())
	require.NoError(t, err)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	am := oidc.TestAuthMethod(t,
		conn, databaseWrapper,
		o.PublicId,
		oidc.ActivePrivateState,
		tpClientId, oidc.ClientSecret(tpClientSecret),
		oidc.WithName("default"),
		oidc.WithDescription("default"),
		oidc.WithCertificates(tpCert[0]),
		oidc.WithSigningAlgs(oidc.Alg(tpAlg)),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, tp.Addr())[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost/")[0]),
	)
	wireAuthMethod := &pb.AuthMethod{
		Id:                          am.GetPublicId(),
		ScopeId:                     am.GetScopeId(),
		Scope:                       &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()},
		Name:                        wrapperspb.String(am.GetName()),
		Description:                 wrapperspb.String(am.GetDescription()),
		CreatedTime:                 am.GetCreateTime().GetTimestamp(),
		UpdatedTime:                 am.GetUpdateTime().GetTimestamp(),
		Version:                     am.GetVersion(),
		Type:                        oidc.Subtype.String(),
		AuthorizedActions:           oidcAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
		Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
			OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
				ApiUrlPrefix:      wrapperspb.String(am.GetApiUrl()),
				CallbackUrl:       fmt.Sprintf("%s/v1/auth-methods/oidc:authenticate:callback", am.GetApiUrl()),
				ClientId:          wrapperspb.String(am.GetClientId()),
				ClientSecretHmac:  am.GetClientSecretHmac(),
				Issuer:            wrapperspb.String(am.GetIssuer()),
				State:             am.GetOperationalState(),
				IdpCaCerts:        []string{tp.CACert()},
				SigningAlgorithms: []string{string(tpAlg)},
			},
		},
	}

	tested, err := authmethods.NewService(ctx, kmsCache, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn, ldapRepoFn, authMethodRepoFn, 1000)
	require.NoError(t, err, "Error when getting new auth_method service.")
	cases := []struct {
		name    string
		id      string
		mask    []string
		item    *pb.AuthMethod
		want    *pb.AuthMethod
		err     error
		wantErr bool
	}{
		{
			name: "Update an Existing AuthMethod",
			id:   am.GetPublicId(),
			mask: []string{"name", "description", "attributes.dry_run"},
			item: &pb.AuthMethod{
				Name:        wrapperspb.String("updated"),
				Description: wrapperspb.String("updated"),
				Version:     am.GetVersion(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						DryRun: true,
					},
				},
			},
			want: func() *pb.AuthMethod {
				c := proto.Clone(wireAuthMethod).(*pb.AuthMethod)
				c.Name = wrapperspb.String("updated")
				c.Description = wrapperspb.String("updated")
				c.GetOidcAuthMethodsAttributes().DryRun = true
				return c
			}(),
		},
		{
			name: "Update To Make Not Complete",
			id:   am.GetPublicId(),
			mask: []string{"attributes.issuer"},
			item: &pb.AuthMethod{
				Version: am.GetVersion(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						DryRun: true,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Update To Make Not Validated",
			id:   am.GetPublicId(),
			mask: []string{"attributes.signing_algorithms"},
			item: &pb.AuthMethod{
				Version: am.GetVersion(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						DryRun:            true,
						SigningAlgorithms: []string{string(oidc.RS512)},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Update dry run with force",
			id:   am.GetPublicId(),
			mask: []string{"name"},
			item: &pb.AuthMethod{
				Version: am.GetVersion(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						DryRun:                            true,
						DisableDiscoveredConfigValidation: true,
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dryUpdated, err := tested.UpdateAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
				&pbs.UpdateAuthMethodRequest{
					Id:         tc.id,
					Item:       tc.item,
					UpdateMask: &field_mask.FieldMask{Paths: tc.mask},
				})

			// TODO: When handlers move to domain errors remove wantErr and rely errors.Match here.
			if tc.err != nil || tc.wantErr {
				require.Error(t, err)
				if tc.err != nil {
					assert.True(t, errors.Is(err, tc.err))
				}
				return
			}
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(
				dryUpdated.GetItem(),
				tc.want,
				protocmp.Transform(),
				protocmp.SortRepeatedFields(dryUpdated),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			))

			got, err := tested.GetAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), &pbs.GetAuthMethodRequest{Id: tc.id})
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(
				got.GetItem(),
				wireAuthMethod,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			))
		})
	}
}

func TestChangeState_OIDC(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kmsCache)
	}
	authMethodRepoFn := func() (*am.AuthMethodRepository, error) {
		return am.NewAuthMethodRepository(ctx, rw, rw, kmsCache)
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
	tpCert, err := oidc.ParseCertificates(ctx, tp.CACert())
	require.NoError(t, err)

	incompleteAm := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, "inactive", "client id", "secret",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]))
	oidcam := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, "inactive", tpClientId, oidc.ClientSecret(tpClientSecret),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, tp.Addr())[0]), oidc.WithSigningAlgs(oidc.Alg(tpAlg)), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://example.callback:58")[0]), oidc.WithCertificates(tpCert...))
	mismatchedAM := oidc.TestAuthMethod(t, conn, databaseWrapper, o.PublicId, "inactive", "different_client_id", oidc.ClientSecret(tpClientSecret),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, tp.Addr())[0]), oidc.WithSigningAlgs(oidc.EdDSA), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://example.callback:58")[0]), oidc.WithCertificates(tpCert...))

	s, err := authmethods.NewService(ctx, kmsCache, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn, ldapRepoFn, authMethodRepoFn, 1000)
	require.NoError(t, err, "Error when getting new auth_method service.")

	wantTemplate := &pb.AuthMethod{
		Id:          oidcam.GetPublicId(),
		ScopeId:     oidcam.GetScopeId(),
		CreatedTime: oidcam.CreateTime.GetTimestamp(),
		UpdatedTime: oidcam.UpdateTime.GetTimestamp(),
		Type:        oidc.Subtype.String(),
		Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
			OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
				Issuer:            wrapperspb.String(oidcam.GetIssuer()),
				ClientId:          wrapperspb.String(tpClientId),
				ClientSecretHmac:  "<hmac>",
				State:             string(oidc.InactiveState),
				CallbackUrl:       "https://example.callback:58/v1/auth-methods/oidc:authenticate:callback",
				ApiUrlPrefix:      wrapperspb.String("https://example.callback:58"),
				SigningAlgorithms: []string{string(tpAlg)},
				IdpCaCerts:        []string{tp.CACert()},
			},
		},
		Version: 1,
		Scope: &scopepb.ScopeInfo{
			Id:            o.GetPublicId(),
			Type:          o.GetType(),
			ParentScopeId: scope.Global.String(),
		},
		AuthorizedActions:           oidcAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
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
			req: &pbs.ChangeStateRequest{
				Id:      pwam.GetPublicId(),
				Version: pwam.GetVersion(),
				Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
					OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
						State: "inactive",
					},
				},
			},
			err: true,
		},
		{
			name: "No Version Specified",
			req: &pbs.ChangeStateRequest{
				Id: oidcam.GetPublicId(),
				Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
					OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
						State: "inactive",
					},
				},
			},
			err: true,
		},
		{
			name: "Keep Inactive",
			req: &pbs.ChangeStateRequest{
				Id:      oidcam.GetPublicId(),
				Version: oidcam.GetVersion(),
				Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
					OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
						State: "inactive",
					},
				},
			},
			res: &pbs.ChangeStateResponse{Item: func() *pb.AuthMethod {
				am := proto.Clone(wantTemplate).(*pb.AuthMethod)
				return am
			}()},
		},
		{
			name: "Make Incomplete Private",
			req: &pbs.ChangeStateRequest{
				Id:      incompleteAm.GetPublicId(),
				Version: oidcam.GetVersion(),
				Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
					OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
						State: "active-private",
					},
				},
			},
			err: true,
		},
		{
			name: "Make Incomplete Public",
			req: &pbs.ChangeStateRequest{
				Id:      incompleteAm.GetPublicId(),
				Version: oidcam.GetVersion(),
				Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
					OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
						State: "active-public",
					},
				},
			},
			err: true,
		},
		{
			name: "Mismatched To Public",
			req: &pbs.ChangeStateRequest{
				Id:      mismatchedAM.GetPublicId(),
				Version: mismatchedAM.GetVersion(),
				Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
					OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
						State: "active-public",
					},
				},
			},
			err: true,
		},
		{
			name: "Force Mismatched To Public",
			req: &pbs.ChangeStateRequest{
				Id:      mismatchedAM.GetPublicId(),
				Version: mismatchedAM.GetVersion(),
				Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
					OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
						State:                             "active-public",
						DisableDiscoveredConfigValidation: true,
					},
				},
			},
			res: &pbs.ChangeStateResponse{Item: func() *pb.AuthMethod {
				am := proto.Clone(wantTemplate).(*pb.AuthMethod)
				am.Id = mismatchedAM.PublicId
				am.GetOidcAuthMethodsAttributes().DisableDiscoveredConfigValidation = true
				am.GetOidcAuthMethodsAttributes().State = "active-public"
				am.GetOidcAuthMethodsAttributes().ClientId = wrapperspb.String(mismatchedAM.ClientId)
				am.GetOidcAuthMethodsAttributes().SigningAlgorithms = []string{string(oidc.EdDSA)}
				am.CreatedTime = mismatchedAM.CreateTime.GetTimestamp()
				am.Version = 2
				return am
			}()},
		},
		{
			name: "Make Complete Private",
			req: &pbs.ChangeStateRequest{
				Id: oidcam.GetPublicId(), Version: oidcam.GetVersion(), Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
					OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
						State: "active-private",
					},
				},
			},
			res: &pbs.ChangeStateResponse{Item: func() *pb.AuthMethod {
				am := proto.Clone(wantTemplate).(*pb.AuthMethod)
				am.GetOidcAuthMethodsAttributes().State = "active-private"
				am.Version = 2
				return am
			}()},
		},
		{
			name: "Make Complete Public",
			req: &pbs.ChangeStateRequest{
				Id: oidcam.GetPublicId(), Version: 2, Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
					OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
						State: "active-public",
					},
				},
			},
			res: &pbs.ChangeStateResponse{Item: func() *pb.AuthMethod {
				am := proto.Clone(wantTemplate).(*pb.AuthMethod)
				am.GetOidcAuthMethodsAttributes().State = "active-public"
				am.Version = 3
				return am
			}()},
		},
		{
			name: "Make Complete Inactive",
			req: &pbs.ChangeStateRequest{
				Id: oidcam.GetPublicId(), Version: 3, Attrs: &pbs.ChangeStateRequest_OidcChangeStateAttributes{
					OidcChangeStateAttributes: &pbs.OidcChangeStateAttributes{
						State: "inactive",
					},
				},
			},
			res: &pbs.ChangeStateResponse{Item: func() *pb.AuthMethod {
				am := proto.Clone(wantTemplate).(*pb.AuthMethod)
				am.GetOidcAuthMethodsAttributes().State = "inactive"
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
			if got.Item.GetOidcAuthMethodsAttributes().CallbackUrl != "" {
				exp := tc.res.Item.GetOidcAuthMethodsAttributes().CallbackUrl
				gVal := got.Item.GetOidcAuthMethodsAttributes().CallbackUrl
				matches, err := regexp.MatchString(exp, gVal)
				require.NoError(err)
				assert.True(matches, "%q doesn't match %q", gVal, exp)
			}
			got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil

			assert.Empty(
				cmp.Diff(
					got,
					tc.res,
					protocmp.Transform(),
					protocmp.IgnoreFields(&pb.OidcAuthMethodAttributes{}, "client_secret_hmac", "callback_url"),
					cmpopts.SortSlices(func(a, b string) bool {
						return a < b
					}),
					cmpopts.SortSlices(func(a, b protocmp.Message) bool {
						return a.String() < b.String()
					}),
				),
				"ChangeState() got response %q, wanted %q", got, tc.res,
			)
		})
	}
}

func TestAuthenticate_OIDC_Start(t *testing.T) {
	s := getSetup(t)

	cases := []struct {
		name       string
		request    *pbs.AuthenticateRequest
		beforeTest func(t *testing.T)
		wantErr    error
	}{
		{
			name: "no command",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: s.authMethod.GetPublicId(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "bad command",
			request: &pbs.AuthenticateRequest{
				Command:      "bad",
				AuthMethodId: s.authMethod.GetPublicId(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "no auth method id",
			request: &pbs.AuthenticateRequest{
				Command: "start",
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "good request, no attributes",
			request: &pbs.AuthenticateRequest{
				Command:      "start",
				AuthMethodId: s.authMethod.GetPublicId(),
			},
		},
		{
			name: "auth method does not exist",
			request: &pbs.AuthenticateRequest{
				Command:      "start",
				AuthMethodId: "amoidc_1234",
				Attrs: &pbs.AuthenticateRequest_OidcStartAttributes{
					OidcStartAttributes: &pbs.OidcStartAttributes{
						RoundtripPayload: func() *structpb.Struct {
							ret, err := structpb.NewStruct(map[string]any{
								"foo": "bar",
								"baz": true,
							})
							require.NoError(t, err)
							return ret
						}(),
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "auth method is inactive",
			beforeTest: func(t *testing.T) {
				r, err := s.oidcRepoFn()
				require.NoError(t, err)
				_, err = r.MakeInactive(s.ctx, s.authMethod.GetPublicId(), 2)
				require.NoError(t, err)

				t.Cleanup(func() {
					_, err = r.MakePublic(s.ctx, s.authMethod.GetPublicId(), 3)
					require.NoError(t, err)
				})
			},
			request: &pbs.AuthenticateRequest{
				Command:      "start",
				AuthMethodId: s.authMethod.GetPublicId(),
				Attrs: &pbs.AuthenticateRequest_OidcStartAttributes{
					OidcStartAttributes: &pbs.OidcStartAttributes{
						RoundtripPayload: func() *structpb.Struct {
							ret, err := structpb.NewStruct(map[string]any{
								"foo": "bar",
								"baz": true,
							})
							require.NoError(t, err)
							return ret
						}(),
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.FailedPrecondition),
		},
		// NOTE: We can't really test bad roundtrip payload attributes because
		// any type structpb lets us use in creation will be valid for JSON, and
		// attempting to force with e.g. json.RawMessage causes structpb to
		// error. This is okay; in the real world anything coming in would
		// _have_ to be valid JSON because it came in on the JSON API
		// successfully!
		//
		// The below test is really testing that it doesn't error; it won't be
		// until a test all the way through the token step that we can verify
		// the underlying functionality, at least without some very onerous
		// decryption steps. Not worth it; just validate once we perform all
		// steps!
		{
			name: "roundtrip payload attributes",
			request: &pbs.AuthenticateRequest{
				Command:      "start",
				AuthMethodId: s.authMethod.GetPublicId(),
				Attrs: &pbs.AuthenticateRequest_OidcStartAttributes{
					OidcStartAttributes: &pbs.OidcStartAttributes{
						RoundtripPayload: func() *structpb.Struct {
							ret, err := structpb.NewStruct(map[string]any{
								"foo": "bar",
								"baz": true,
							})
							require.NoError(t, err)
							return ret
						}(),
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.beforeTest != nil {
				tc.beforeTest(t)
			}

			assert, require := assert.New(t), require.New(t)
			got, err := s.authMethodService.Authenticate(auth.DisabledAuthTestContext(s.iamRepoFn, s.org.GetPublicId()), tc.request)
			if tc.wantErr != nil {
				assert.Error(err)
				assert.Truef(errors.Is(err, tc.wantErr), "Got %#v, wanted %#v", err, tc.wantErr)
				return
			}
			require.NoError(err)
			require.Equal(got.GetCommand(), "start")
			// We can't really compare directly as a lot of the values contain
			// random data, so just verify existence
			got.GetAuthTokenResponse()
			require.NotNil(got.GetOidcAuthMethodAuthenticateStartResponse())
			require.NotEmpty(got.GetOidcAuthMethodAuthenticateStartResponse().GetAuthUrl())
			require.NotEmpty(got.GetOidcAuthMethodAuthenticateStartResponse().GetTokenId())
		})
	}
}

func TestAuthenticate_OIDC_Token(t *testing.T) {
	ctx := context.Background()
	s := getSetup(t)
	testAtRepo, err := authtoken.NewRepository(ctx, s.rw, s.rw, s.kmsCache)
	require.NoError(t, err)

	// a reusable test authmethod for the unit tests
	testAuthMethod := oidc.TestAuthMethod(t, s.conn, s.databaseWrapper, s.org.PublicId, oidc.ActivePublicState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]),
		oidc.WithSigningAlgs(oidc.Alg(oidc.RS256)),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://alice.com/callback")[0]))

	testAcct := oidc.TestAccount(t, s.conn, testAuthMethod, "alice")
	testUser := iam.TestUser(t, s.iamRepo, s.org.PublicId, iam.WithAccountIds(testAcct.PublicId))

	cases := []struct {
		name         string
		request      *pbs.AuthenticateRequest
		wantErr      error
		wantErrMatch *errors.Template
	}{
		{
			name: "no command",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: s.authMethod.GetPublicId(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "bad command",
			request: &pbs.AuthenticateRequest{
				Command:      "bad",
				AuthMethodId: s.authMethod.GetPublicId(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "no auth method id",
			request: &pbs.AuthenticateRequest{
				Command: "token",
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "no attributes",
			request: &pbs.AuthenticateRequest{
				Command:      "token",
				AuthMethodId: s.authMethod.GetPublicId(),
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "success",
			request: &pbs.AuthenticateRequest{
				Command:      "token",
				AuthMethodId: s.authMethod.GetPublicId(),
				Attrs: &pbs.AuthenticateRequest_OidcAuthMethodAuthenticateTokenRequest{
					OidcAuthMethodAuthenticateTokenRequest: &pb.OidcAuthMethodAuthenticateTokenRequest{
						TokenId: func() string {
							tokenPublicId, err := authtoken.NewAuthTokenId(ctx)
							require.NoError(t, err)
							oidc.TestPendingToken(t, testAtRepo, testUser, testAcct, tokenPublicId)
							return oidc.TestTokenRequestId(t, s.authMethod, s.kmsCache, 200*time.Second, tokenPublicId)
						}(),
					},
				},
			},
		},
		{
			name: "expired",
			request: &pbs.AuthenticateRequest{
				Command:      "token",
				AuthMethodId: s.authMethod.GetPublicId(),
				Attrs: &pbs.AuthenticateRequest_OidcAuthMethodAuthenticateTokenRequest{
					OidcAuthMethodAuthenticateTokenRequest: &pb.OidcAuthMethodAuthenticateTokenRequest{
						TokenId: func() string {
							tokenPublicId, err := authtoken.NewAuthTokenId(ctx)
							require.NoError(t, err)
							oidc.TestPendingToken(t, testAtRepo, testUser, testAcct, tokenPublicId)
							return oidc.TestTokenRequestId(t, s.authMethod, s.kmsCache, -20*time.Second, tokenPublicId)
						}(),
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
		},
		{
			name: "invalid-token-id-not-encoded-encrypted-proto",
			request: &pbs.AuthenticateRequest{
				Command:      "token",
				AuthMethodId: s.authMethod.GetPublicId(),
				Attrs: &pbs.AuthenticateRequest_OidcAuthMethodAuthenticateTokenRequest{
					OidcAuthMethodAuthenticateTokenRequest: &pb.OidcAuthMethodAuthenticateTokenRequest{
						TokenId: "bad-token-id",
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.Internal),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := s.authMethodService.Authenticate(auth.DisabledAuthTestContext(s.iamRepoFn, s.org.GetPublicId()), tc.request)
			if tc.wantErr != nil {
				require.Error(err)
				assert.Truef(errors.Is(err, tc.wantErr), "Got %#v, wanted %#v", err, tc.wantErr)
				return
			}
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "Got %#v, wanted %#v", err, tc.wantErrMatch.Code)
				return
			}
			require.NoError(err)
			require.Equal(got.GetCommand(), "token")
			require.NotNil(got.GetAuthTokenResponse())
			require.NotEmpty(got.GetAuthTokenResponse().GetToken())
		})
	}
}

func TestAuthenticate_OIDC_Callback_ErrorRedirect(t *testing.T) {
	s := getSetup(t)

	directErrorCases := []struct {
		name string
		req  *pbs.AuthenticateRequest
	}{
		{
			name: "No Code Or Error",
			req: &pbs.AuthenticateRequest{
				AuthMethodId: s.authMethod.GetPublicId(),
				Command:      "callback",
				Attrs: &pbs.AuthenticateRequest_OidcAuthMethodAuthenticateCallbackRequest{
					OidcAuthMethodAuthenticateCallbackRequest: &pb.OidcAuthMethodAuthenticateCallbackRequest{
						State: "anything",
					},
				},
			},
		},
		{
			name: "No Auth Method Id",
			req: &pbs.AuthenticateRequest{
				Command: "callback",
				Attrs: &pbs.AuthenticateRequest_OidcAuthMethodAuthenticateCallbackRequest{
					OidcAuthMethodAuthenticateCallbackRequest: &pb.OidcAuthMethodAuthenticateCallbackRequest{
						Code:  "anythingworks",
						State: "anything",
					},
				},
			},
		},
		{
			name: "No State",
			req: &pbs.AuthenticateRequest{
				AuthMethodId: s.authMethod.GetPublicId(),
				Command:      "callback",
				Attrs: &pbs.AuthenticateRequest_OidcAuthMethodAuthenticateCallbackRequest{
					OidcAuthMethodAuthenticateCallbackRequest: &pb.OidcAuthMethodAuthenticateCallbackRequest{
						Code: "anythingworks",
					},
				},
			},
		},
	}
	for _, tc := range directErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.authMethodService.Authenticate(auth.DisabledAuthTestContext(s.iamRepoFn, s.org.GetPublicId()), tc.req)
			require.Error(t, err)
		})
	}

	redirectUrlErrorCases := []struct {
		name        string
		attrs       *pb.OidcAuthMethodAuthenticateCallbackRequest
		errorSubStr string
	}{
		{
			name: "Cant decrypt state",
			attrs: &pb.OidcAuthMethodAuthenticateCallbackRequest{
				Code:  "anythingworkshere",
				State: "cant decrypt this!",
			},
			errorSubStr: url.QueryEscape("unable to decode message"),
		},
		{
			name: "OIDC Error",
			attrs: &pb.OidcAuthMethodAuthenticateCallbackRequest{
				State:            "foo",
				Error:            "some_error",
				ErrorDescription: "error description",
			},
			errorSubStr: url.QueryEscape("error description"),
		},
	}
	for _, tc := range redirectUrlErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.authMethodService.Authenticate(auth.DisabledAuthTestContext(s.iamRepoFn, s.org.GetPublicId()),
				&pbs.AuthenticateRequest{
					AuthMethodId: s.authMethod.GetPublicId(),
					Command:      "callback",
					Attrs: &pbs.AuthenticateRequest_OidcAuthMethodAuthenticateCallbackRequest{
						OidcAuthMethodAuthenticateCallbackRequest: tc.attrs,
					},
				})

			require.NoError(t, err)
			respAttrs := got.GetOidcAuthMethodAuthenticateCallbackResponse()
			assert.Contains(t, respAttrs.FinalRedirectUrl, fmt.Sprintf("%s/authentication-error?", s.authMethod.GetApiUrl()))
			u, err := url.Parse(respAttrs.GetFinalRedirectUrl())
			require.NoError(t, err)
			assert.Contains(t, u.RawQuery, tc.errorSubStr)
		})
	}
}
