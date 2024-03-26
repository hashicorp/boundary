// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/alias"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pb_api "github.com/hashicorp/boundary/internal/gen/controller/api"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	pberrors "github.com/hashicorp/boundary/internal/gen/errors"
	"github.com/hashicorp/boundary/internal/gen/testing/interceptor"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/go-hclog"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_unaryCtxInterceptor(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kmsCache)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
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
			Path:    req.URL.Path,
			Method:  req.Method,
			EventId: "test-event-id",
			TraceId: "test-trace-id",
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

	returnCtxHandler := func(ctx context.Context, req any) (any, error) {
		return ctx, nil
	}

	c := event.TestEventerConfig(t, "Test_unaryCtxInterceptor", event.TestWithAuditSink(t), event.TestWithObservationSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	testEventer, err := event.NewEventer(testLogger, testLock, "Test_unaryCtxInterceptor", c.EventerConfig)
	require.NoError(t, err)

	tests := []struct {
		name                   string
		requestCtx             context.Context
		iamRepoFn              common.IamRepoFactory
		authTokenRepoFn        common.AuthTokenRepoFactory
		serversRepoFn          common.ServersRepoFactory
		kms                    *kms.Kms
		eventer                *event.Eventer
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
			wantFactoryErr:         true,
			wantFactoryErrMatch:    errors.T(errors.InvalidParameter),
			wantFactoryErrContains: "missing server repo function",
		},
		{
			name:                   "missing-kms",
			requestCtx:             newReqCtx(validGatewayTicket),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			eventer:                testEventer,
			wantFactoryErr:         true,
			wantFactoryErrMatch:    errors.T(errors.InvalidParameter),
			wantFactoryErrContains: "missing kms",
		},
		{
			name:                   "missing-eventer",
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:         testEventer,
			ticket:          validGatewayTicket,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			interceptor, err := requestCtxUnaryInterceptor(factoryCtx, tt.iamRepoFn, tt.authTokenRepoFn, tt.serversRepoFn, nil, nil, nil, tt.kms, tt.ticket, tt.eventer)
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

func Test_streamCtxInterceptor(t *testing.T) {
	t.Parallel()
	factoryCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(context.Background(), rw, rw, kmsCache)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(factoryCtx, rw, rw, kmsCache)
	}

	validGatewayTicket := "valid-ticket"

	o, _ := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kmsCache, o.GetPublicId())
	encToken, err := authtoken.EncryptToken(factoryCtx, kmsCache, o.GetPublicId(), at.GetPublicId(), at.GetToken())
	require.NoError(t, err)
	tokValue := at.GetPublicId() + "_" + encToken

	newReqCtx := func(gwTicket string) context.Context {
		req := httptest.NewRequest("GET", "http://127.0.0.1/v1/scopes/o_1", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokValue))
		// Add values for authn/authz checking
		requestInfo := authpb.RequestInfo{
			Path:    req.URL.Path,
			Method:  req.Method,
			EventId: "test-event-id",
			TraceId: "test-trace-id",
		}
		requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = auth.GetTokenFromRequest(context.TODO(), kmsCache, req)
		requestInfo.Ticket = gwTicket // allows the grpc-gateway to verify the request info came from it's in-memory companion http proxy
		marshalledRequestInfo, err := proto.Marshal(&requestInfo)
		require.NoError(t, err)
		md := metadata.Pairs(requestInfoMdKey, base58.FastBase58Encoding(marshalledRequestInfo))
		mdCtx := metadata.NewIncomingContext(factoryCtx, md)

		md, ok := metadata.FromIncomingContext(mdCtx)
		require.True(t, ok)
		require.NotNil(t, md)

		return mdCtx
	}

	c := event.TestEventerConfig(t, "Test_streamCtxInterceptor", event.TestWithAuditSink(t), event.TestWithObservationSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	testEventer, err := event.NewEventer(testLogger, testLock, "Test_streamCtxInterceptor", c.EventerConfig)
	require.NoError(t, err)
	tests := []struct {
		name                   string
		requestCtx             context.Context
		iamRepoFn              common.IamRepoFactory
		authTokenRepoFn        common.AuthTokenRepoFactory
		serversRepoFn          common.ServersRepoFactory
		kms                    *kms.Kms
		eventer                *event.Eventer
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
			wantFactoryErr:         true,
			wantFactoryErrMatch:    errors.T(errors.InvalidParameter),
			wantFactoryErrContains: "missing server repo function",
		},
		{
			name:                   "missing-kms",
			requestCtx:             newReqCtx(validGatewayTicket),
			iamRepoFn:              iamRepoFn,
			authTokenRepoFn:        atRepoFn,
			serversRepoFn:          serversRepoFn,
			eventer:                testEventer,
			wantFactoryErr:         true,
			wantFactoryErrMatch:    errors.T(errors.InvalidParameter),
			wantFactoryErrContains: "missing kms",
		},
		{
			name:                   "missing-eventer",
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
			eventer:                testEventer,
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
			eventer:                testEventer,
			ticket:                 validGatewayTicket,
			wantRequestErr:         true,
			wantRequestErrMatch:    errors.T(errors.Internal),
			wantRequestErrContains: "No metadata",
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:                testEventer,
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
			eventer:         testEventer,
			ticket:          validGatewayTicket,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			interceptor, err := requestCtxStreamInterceptor(factoryCtx, tt.iamRepoFn, tt.authTokenRepoFn, tt.serversRepoFn, nil, nil, nil, tt.kms, tt.ticket, tt.eventer)
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

			info := &grpc.StreamServerInfo{
				FullMethod:     "FakeMethod",
				IsClientStream: true,
			}
			var hdCtx context.Context

			hd := func(srv interface{}, stream grpc.ServerStream) error {
				hdCtx = stream.Context()
				return nil
			}
			m := &streamMock{ctx: tt.requestCtx}
			err = interceptor(nil, m, info, hd)
			if tt.wantRequestErr {
				require.Error(err)
				if tt.wantRequestErrMatch != nil {
					assert.Truef(errors.Match(tt.wantRequestErrMatch, err), "want err code: %q got: %q", tt.wantRequestErrMatch.Code, err)
				}
				if tt.wantRequestErrContains != "" {
					assert.Contains(err.Error(), tt.wantRequestErrContains)
				}
				return
			}
			require.NoError(err)
			verifyResults := auth.Verify(hdCtx.(context.Context))
			assert.NotEmpty(verifyResults)
		})
	}
}

type streamMock struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *streamMock) Context() context.Context {
	return m.ctx
}

func (m *streamMock) Send(req *httpbody.HttpBody) error {
	panic("send not implemented")
}

func (m *streamMock) RecvToClient() (*httpbody.HttpBody, error) {
	panic("recv not implemented")
}

func Test_aliasResolutionInterceptor(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	aliasRepoFn := func() (*alias.Repository, error) {
		return alias.NewRepository(context.Background(), rw, rw, kmsCache)
	}

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test-target")
	al := talias.TestAlias(t, rw, "test-alias.example", talias.WithDestinationId(tar.GetPublicId()))
	alWithoutDest := talias.TestAlias(t, rw, "no-destination.alias")

	interceptor := aliasResolutionInterceptor(ctx, aliasRepoFn)
	require.NotNil(t, interceptor)

	returnCtxHandler := func(ctx context.Context, req any) (any, error) {
		return ctx, nil
	}
	info := &grpc.UnaryServerInfo{
		FullMethod: "FakeMethod",
	}

	cases := []struct {
		name            string
		req             proto.Message
		wantModifiedReq proto.Message
		wantAlias       *alias.Alias
		errorIs         error
	}{
		{
			name:            "non aliasable request",
			req:             &pbs.GetAccountRequest{Id: "test"},
			wantModifiedReq: &pbs.GetAccountRequest{Id: "test"},
		},
		{
			name:            "non aliasable request with valid alias",
			req:             &pbs.GetAccountRequest{Id: al.GetValue()},
			wantModifiedReq: &pbs.GetAccountRequest{Id: al.GetValue()},
		},
		{
			name:            "aliasable request with id",
			req:             &pbs.GetTargetRequest{Id: tar.GetPublicId()},
			wantModifiedReq: &pbs.GetTargetRequest{Id: tar.GetPublicId()},
		},
		{
			name:            "aliasable request with alias",
			req:             &pbs.GetTargetRequest{Id: al.GetValue()},
			wantModifiedReq: &pbs.GetTargetRequest{Id: tar.GetPublicId()},
			wantAlias: &alias.Alias{
				PublicId:      al.GetPublicId(),
				Value:         al.GetValue(),
				DestinationId: tar.GetPublicId(),
			},
		},
		{
			name:            "aliasable request with unknown alias",
			req:             &pbs.GetTargetRequest{Id: "not.a.registered.alias"},
			wantModifiedReq: &pbs.GetTargetRequest{Id: "not.a.registered.alias"},
			errorIs:         handlers.UnauthenticatedError(),
		},
		{
			name:            "aliasable request with destinationless alias",
			req:             &pbs.GetTargetRequest{Id: alWithoutDest.GetValue()},
			wantModifiedReq: &pbs.GetTargetRequest{Id: alWithoutDest.GetValue()},
			errorIs:         handlers.UnauthenticatedError(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			req := proto.Clone(tc.req)
			retCtx, err := interceptor(ctx, req, info, returnCtxHandler)
			assert.Empty(t, cmp.Diff(tc.wantModifiedReq, req, protocmp.Transform()))
			if tc.errorIs != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.errorIs)
				return
			}
			ctxAlias := alias.FromContext(retCtx.(context.Context))
			if tc.wantAlias == nil {
				require.Nil(t, ctxAlias)
				return
			}
			require.NotNil(t, ctxAlias)
			assert.EqualValues(t, tc.wantAlias, ctxAlias)
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

func Test_statusCodeInterceptor(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name           string
		wantStatusCode int
		wantErr        bool
	}{
		{
			name:           "nil-nil",
			wantStatusCode: http.StatusNoContent,
		},
		{
			name:    "nil-err",
			wantErr: true,
		},
		{
			name: "hello",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			statusInterceptor := statusCodeInterceptor(ctx)
			client := startTestGreeterService(t, &testGreeter{}, statusInterceptor)
			var header metadata.MD
			_, err := client.SayHello(
				context.Background(),
				&interceptor.SayHelloRequest{Name: tt.name},
				grpc.Header(&header),
			)

			if tt.wantErr {
				assert.Error(err)
			}
			statusHdr := header.Get(handlers.StatusCodeHeader)
			if tt.wantStatusCode > 0 {
				require.Len(statusHdr, 1)
				code, err := strconv.Atoi(statusHdr[0])
				require.NoError(err)
				assert.Equal(tt.wantStatusCode, code)
			} else {
				require.Len(statusHdr, 0)
			}
		})
	}
}

func Test_workerRequestInfoInterceptor(t *testing.T) {
	factoryCtx := context.Background()
	requestCtx := context.Background()

	returnCtxHandler := func(ctx context.Context, req any) (any, error) {
		return ctx, nil
	}

	c := event.TestEventerConfig(t, "Test_unaryCtxInterceptor", event.TestWithAuditSink(t), event.TestWithObservationSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	testEventer, err := event.NewEventer(testLogger, testLock, "Test_unaryCtxInterceptor", c.EventerConfig)
	require.NoError(t, err)

	tests := []struct {
		name                   string
		requestCtx             context.Context
		eventer                *event.Eventer
		wantFactoryErr         bool
		wantFactoryErrMatch    *errors.Template
		wantFactoryErrContains string
		wantRequestErr         bool
		wantRequestErrMatch    *errors.Template
		wantRequestErrContains string
	}{
		{
			name:                   "missing-eventer",
			requestCtx:             requestCtx,
			wantFactoryErr:         true,
			wantFactoryErrMatch:    errors.T(errors.InvalidParameter),
			wantFactoryErrContains: "missing eventer",
		},

		{
			name:       "valid",
			requestCtx: requestCtx,
			eventer:    testEventer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			interceptor, err := workerRequestInfoInterceptor(factoryCtx, tt.eventer)
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
			requestInfo, found := event.RequestInfoFromContext(retCtx.(context.Context))
			require.True(found)
			assert.NotNil(requestInfo)
			assert.NotEmpty(requestInfo.Id)
			assert.NotEmpty(requestInfo.EventId)
			assert.Equal("FakeMethod", requestInfo.Method)

			eventer, found := event.EventerFromContext(retCtx.(context.Context))
			require.True(found)
			assert.NotNil(eventer)
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
	case "nil-nil":
		return nil, nil
	case "nil-err":
		return nil, errors.New(ctx, errors.Internal, op, "nil response error msg")
	default:
		return &interceptor.SayHelloResponse{Message: "hello"}, nil
	}
}
