package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pb_api "github.com/hashicorp/boundary/internal/gen/controller/api"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	pberrors "github.com/hashicorp/boundary/internal/gen/errors"
	"github.com/hashicorp/boundary/internal/gen/testing/interceptor"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

func Test_requestCtxInterceptor(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kmsCache)
	}
	serversRepoFn := func() (*servers.Repository, error) {
		return servers.NewRepository(rw, rw, kmsCache)
	}

	validGatewayTicket := "valid-ticket"

	o, _ := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kmsCache, o.GetPublicId())
	encToken, err := authtoken.EncryptToken(context.Background(), kmsCache, o.GetPublicId(), at.GetPublicId(), at.GetToken())
	require.NoError(t, err)
	tokValue := at.GetPublicId() + "_" + encToken

	newReqCtx := func(gwTicket string) context.Context {
		req := httptest.NewRequest("GET", "http://127.0.0.1/v1/scopes/o_1", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokValue))
		// Add values for authn/authz checking
		requestInfo := authpb.RequestInfo{
			Path:   req.URL.Path,
			Method: req.Method,
		}
		requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = auth.GetTokenFromRequest(context.TODO(), kmsCache, req)
		requestInfo.Ticket = gwTicket // allows the grpc-gateway to verify the request info came from it's in-memory companion http proxy
		marshalledRequestInfo, err := proto.Marshal(&requestInfo)
		require.NoError(t, err)
		md := metadata.Pairs(requestInfoMdKey, base58.FastBase58Encoding(marshalledRequestInfo))
		mdCtx := metadata.NewIncomingContext(context.Background(), md)

		md, ok := metadata.FromIncomingContext(mdCtx)
		require.True(t, ok)
		require.NotNil(t, md)

		return mdCtx
	}

	factoryCtx := context.Background()

	returnCtxHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return ctx, nil
	}

	tests := []struct {
		name                   string
		requestCtx             context.Context
		iamRepoFn              common.IamRepoFactory
		authTokenRepoFn        common.AuthTokenRepoFactory
		serversRepoFn          common.ServersRepoFactory
		kms                    *kms.Kms
		ticket                 string
		wantFactoryErr         bool
		wantFactoryErrMatch    *errors.Template
		wantFactoryErrContains string
		wantRequestErr         bool
		wantRequestErrMatch    *errors.Template
		wantRequestErrContains string
	}{
		{
			name:                   "missing-iam-repo",
			requestCtx:             newReqCtx(validGatewayTicket),
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			wantFactoryErr:         true,
			wantFactoryErrMatch:    errors.T(errors.InvalidParameter),
			wantFactoryErrContains: "missing iam repo",
		},
		{
			name:                   "missing-at-repo",
			requestCtx:             newReqCtx(validGatewayTicket),
			iamRepoFn:              iamRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			wantFactoryErr:         true,
			wantFactoryErrMatch:    errors.T(errors.InvalidParameter),
			wantFactoryErrContains: "missing auth token repo",
		},
		{
			name:                   "missing-servers-repo",
			requestCtx:             newReqCtx(validGatewayTicket),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			kms:                    kmsCache,
			wantFactoryErr:         true,
			wantFactoryErrMatch:    errors.T(errors.InvalidParameter),
			wantFactoryErrContains: "missing servers repo function",
		},
		{
			name:                   "missing-kms",
			requestCtx:             newReqCtx(validGatewayTicket),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			wantFactoryErr:         true,
			wantFactoryErrMatch:    errors.T(errors.InvalidParameter),
			wantFactoryErrContains: "missing kms",
		},
		{
			name:                   "missing-factory-ticket",
			requestCtx:             newReqCtx(validGatewayTicket),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			wantFactoryErr:         true,
			wantFactoryErrMatch:    errors.T(errors.InvalidParameter),
			wantFactoryErrContains: "missing ticket",
		},
		{
			name:                   "missing-metadata",
			requestCtx:             context.Background(),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			ticket:                 validGatewayTicket,
			wantRequestErr:         true,
			wantRequestErrMatch:    errors.T(errors.Internal),
			wantRequestErrContains: "No metadata",
		},
		{
			name: "missing-request-info-metadata",
			requestCtx: func() context.Context {
				md := metadata.Pairs("greeter-md", "hello")
				return metadata.NewIncomingContext(context.Background(), md)
			}(),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			ticket:                 validGatewayTicket,
			wantRequestErr:         true,
			wantRequestErrMatch:    errors.T(errors.Internal),
			wantRequestErrContains: "Missing request metadata",
		},
		{
			name: "too-many-request-info-metadata",
			requestCtx: func() context.Context {
				md := metadata.Pairs(requestInfoMdKey, "first", requestInfoMdKey, "second")
				return metadata.NewIncomingContext(context.Background(), md)
			}(),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			ticket:                 validGatewayTicket,
			wantRequestErr:         true,
			wantRequestErrMatch:    errors.T(errors.Internal),
			wantRequestErrContains: "expected 1 value",
		},
		{
			name: "request-info-metadata-not-encoded",
			requestCtx: func() context.Context {
				md := metadata.Pairs(requestInfoMdKey, "hello")
				return metadata.NewIncomingContext(context.Background(), md)
			}(),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			ticket:                 validGatewayTicket,
			wantRequestErr:         true,
			wantRequestErrMatch:    errors.T(errors.Internal),
			wantRequestErrContains: "unable to decode request info",
		},
		{
			name: "request-info-metadata-not-proto",
			requestCtx: func() context.Context {
				md := metadata.Pairs(requestInfoMdKey, base58.FastBase58Encoding([]byte("hello")))
				return metadata.NewIncomingContext(context.Background(), md)
			}(),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			ticket:                 validGatewayTicket,
			wantRequestErr:         true,
			wantRequestErrMatch:    errors.T(errors.Internal),
			wantRequestErrContains: "unable to unmarshal request info",
		},
		{
			name: "request-info-metadata-not-proto",
			requestCtx: func() context.Context {
				md := metadata.Pairs(requestInfoMdKey, base58.FastBase58Encoding([]byte("hello")))
				return metadata.NewIncomingContext(context.Background(), md)
			}(),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			ticket:                 validGatewayTicket,
			wantRequestErr:         true,
			wantRequestErrMatch:    errors.T(errors.Internal),
			wantRequestErrContains: "unable to unmarshal request info",
		},
		{
			name:                   "missing-request-ticket",
			requestCtx:             newReqCtx(""),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			ticket:                 "validGatewayTicket",
			wantRequestErr:         true,
			wantRequestErrMatch:    errors.T(errors.Internal),
			wantRequestErrContains: "Invalid context (missing ticket)",
		},
		{
			name:                   "bad-ticket",
			requestCtx:             newReqCtx("bad-ticket"),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			kms:                    kmsCache,
			ticket:                 "validGatewayTicket",
			wantRequestErr:         true,
			wantRequestErrMatch:    errors.T(errors.Internal),
			wantRequestErrContains: "Invalid context (bad ticket)",
		},
		{
			name:            "valid",
			requestCtx:      newReqCtx(validGatewayTicket),
			iamRepoFn:       iamRepoFn,
			authTokenRepoFn: atRepoFn,
			serversRepoFn:   serversRepoFn,
			kms:             kmsCache,
			ticket:          validGatewayTicket,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			interceptor, err := requestCtxInterceptor(factoryCtx, tt.iamRepoFn, tt.authTokenRepoFn, tt.serversRepoFn, tt.kms, tt.ticket)
			if tt.wantFactoryErr {
				require.Error(err)
				assert.Nil(interceptor)
				if tt.wantFactoryErrMatch != nil {
					assert.Truef(errors.Match(tt.wantFactoryErrMatch, err), "want err code: %q got: %q", tt.wantFactoryErrMatch.Code, err)
				}
				if tt.wantFactoryErrContains != "" {
					assert.Contains(err.Error(), tt.wantFactoryErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(interceptor)

			info := &grpc.UnaryServerInfo{
				FullMethod: "FakeMethod",
			}
			retCtx, err := interceptor(tt.requestCtx, nil, info, returnCtxHandler)
			if tt.wantRequestErr {
				require.Error(err)
				assert.Nil(retCtx)
				if tt.wantRequestErrMatch != nil {
					assert.Truef(errors.Match(tt.wantRequestErrMatch, err), "want err code: %q got: %q", tt.wantRequestErrMatch.Code, err)
				}
				if tt.wantRequestErrContains != "" {
					assert.Contains(err.Error(), tt.wantRequestErrContains)
				}
				return
			}
			require.NoError(err)
			verifyResults := auth.Verify(retCtx.(context.Context))
			assert.NotEmpty(verifyResults)
		})
	}
}

func Test_errorInterceptor(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name           string
		factoryCtx     context.Context
		wantRequestErr bool
		wantDomainErr  bool
		wantApiErr     bool
	}{
		{
			name:           "domain-error",
			factoryCtx:     ctx,
			wantRequestErr: true,
			wantDomainErr:  true,
		},
		{
			name:           "api-error",
			factoryCtx:     ctx,
			wantRequestErr: true,
			wantApiErr:     true,
		},
		{
			name:       "success",
			factoryCtx: ctx,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.Falsef(tt.wantApiErr && tt.wantDomainErr, "tests can't require both wantApiErr and wantDomainErr")
			errInterceptor := errorInterceptor(tt.factoryCtx)
			client := startTestGreeterService(t, &testGreeter{}, errInterceptor)
			var header metadata.MD
			resp, err := client.SayHello(
				context.Background(),
				&interceptor.SayHelloRequest{Name: tt.name},
				grpc.Header(&header),
			)
			if tt.wantRequestErr {
				require.Error(err)
				domainHdr := header.Get(domainErrHeader)
				apiErrHdr := header.Get(apiErrHeader)
				require.Error(err)
				assert.Nil(resp)
				if tt.wantDomainErr {
					require.Len(domainHdr, 1)
					assert.Len(apiErrHdr, 0)
					decoded, err := base58.FastBase58Decoding(domainHdr[0])
					require.NoError(err)
					var pbErr pberrors.Err
					err = proto.Unmarshal(decoded, &pbErr)
					require.NoError(err)
				}
				if tt.wantApiErr {
					require.Len(apiErrHdr, 1)
					assert.Len(domainHdr, 0)
					decoded, err := base58.FastBase58Decoding(apiErrHdr[0])
					require.NoError(err)
					var pbErr pberrors.ApiError
					err = proto.Unmarshal(decoded, &pbErr)
					require.NoError(err)
				}
				return
			}
			require.NoError(err)
		})
	}

}

type testGreeter struct {
	interceptor.UnimplementedGreeterServiceServer
}

func (g *testGreeter) SayHello(ctx context.Context, req *interceptor.SayHelloRequest) (*interceptor.SayHelloResponse, error) {
	const op = "SayHello"
	switch req.GetName() {
	case "api-error":
		return &interceptor.SayHelloResponse{}, &handlers.ApiError{
			Status: http.StatusInternalServerError,
			Inner: &pb_api.Error{
				Kind:    "internal",
				Op:      op,
				Message: "api error msg",
			},
		}
	case "domain-error":
		return &interceptor.SayHelloResponse{Message: "hello"}, errors.New(ctx, errors.Internal, op, "domain error msg")
	default:
		return &interceptor.SayHelloResponse{Message: "hello"}, nil
	}
}
