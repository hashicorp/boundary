// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package warning

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/globals"
	pbwarnings "github.com/hashicorp/boundary/internal/gen/controller/api"
	opsservices "github.com/hashicorp/boundary/internal/gen/ops/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestApiWarnings(t *testing.T) {
	for i := 1; i <= int(zzzKeepThisLastSentinel); i++ {
		assert.NotNil(t, apiWarning(i).toProto(), "Api warning with code: %d", i)
	}
}

func TestContext(t *testing.T) {
	t.Run("no apiWarning on context", func(t *testing.T) {
		ctx := context.Background()
		assert.Error(t, Warn(ctx, FieldDeprecatedTargetWorkerFilters))
	})

	t.Run("empty apiWarning on context", func(t *testing.T) {
		ctx := newContext(context.Background())
		newW, ok := ctx.Value(warnerContextKey).(*warner)
		assert.True(t, ok)
		assert.Empty(t, newW)
	})
}

func TestWarn(t *testing.T) {
	ctx := newContext(context.Background())
	assert.NoError(t, Warn(ctx, FieldDeprecatedTargetWorkerFilters))

	newW, ok := ctx.Value(warnerContextKey).(*warner)
	assert.True(t, ok)
	assert.Equal(t, &warner{warnings: []*pbwarnings.Warning{
		FieldDeprecatedTargetWorkerFilters.toProto(),
	}}, newW)
}

func TestGrpcGatwayWiring(t *testing.T) {
	ctx := context.Background()

	service := &fakeService{addWarnFunc: func(ctx context.Context) {}}
	grpcSrv := grpc.NewServer(grpc.UnaryInterceptor(GrpcInterceptor(ctx)))
	opsservices.RegisterHealthServiceServer(grpcSrv, service)

	l := bufconn.Listen(int(globals.DefaultMaxRequestSize))
	go grpcSrv.Serve(l)
	t.Cleanup(func() {
		grpcSrv.GracefulStop()
	})

	gwMux := runtime.NewServeMux(
		runtime.WithOutgoingHeaderMatcher(OutgoingHeaderMatcher()),
	)
	require.NoError(t, opsservices.RegisterHealthServiceHandlerFromEndpoint(ctx, gwMux, "", []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return l.Dial()
		}),
	}))

	mux := http.NewServeMux()
	mux.Handle("/health", gwMux)

	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go httpSrv.Serve(lis)
	t.Cleanup(func() {
		assert.NoError(t, httpSrv.Shutdown(ctx))
	})

	t.Run("field apiWarning only", func(t *testing.T) {
		service.addWarnFunc = func(ctx context.Context) {
			Warn(ctx, FieldDeprecatedTargetWorkerFilters)
		}
		resp, err := http.Get(fmt.Sprintf("http://%s/health", lis.Addr().String()))
		require.NoError(t, err)
		got := resp.Header.Get(warningHeader)
		require.NoError(t, err)

		want, err := protojson.Marshal(&pbwarnings.WarningResponse{
			Warnings: []*pbwarnings.Warning{FieldDeprecatedTargetWorkerFilters.toProto()},
		})
		require.NoError(t, err)
		assert.Equal(t, string(want), got)
	})

	t.Run("behavior apiWarning only", func(t *testing.T) {
		service.addWarnFunc = func(ctx context.Context) {
			assert.NoError(t, Warn(ctx, OidcAuthMethodInactiveCannotBeUsed))
		}
		resp, err := http.Get(fmt.Sprintf("http://%s/health", lis.Addr().String()))
		require.NoError(t, err)
		got := resp.Header.Get(warningHeader)
		require.NoError(t, err)

		want, err := protojson.Marshal(&pbwarnings.WarningResponse{
			Warnings: []*pbwarnings.Warning{OidcAuthMethodInactiveCannotBeUsed.toProto()},
		})
		require.NoError(t, err)
		assert.Equal(t, string(want), got)
	})
	t.Run("all apiWarning types", func(t *testing.T) {
		service.addWarnFunc = func(ctx context.Context) {
			assert.NoError(t, Warn(ctx, FieldDeprecatedTargetWorkerFilters))
			assert.NoError(t, Warn(ctx, OidcAuthMethodInactiveCannotBeUsed))
		}
		resp, err := http.Get(fmt.Sprintf("http://%s/health", lis.Addr().String()))
		require.NoError(t, err)
		got := resp.Header.Get(warningHeader)
		require.NoError(t, err)

		want, err := protojson.Marshal(&pbwarnings.WarningResponse{
			Warnings: []*pbwarnings.Warning{
				FieldDeprecatedTargetWorkerFilters.toProto(),
				OidcAuthMethodInactiveCannotBeUsed.toProto(),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, string(want), got)
	})
}

// fakeService is made to
type fakeService struct {
	opsservices.UnimplementedHealthServiceServer
	addWarnFunc func(context.Context)
}

func (f fakeService) GetHealth(ctx context.Context, request *opsservices.GetHealthRequest) (*opsservices.GetHealthResponse, error) {
	f.addWarnFunc(ctx)
	return &opsservices.GetHealthResponse{}, nil
}
