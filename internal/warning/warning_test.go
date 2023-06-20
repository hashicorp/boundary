// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

func TestContext(t *testing.T) {
	t.Run("no warning on context", func(t *testing.T) {
		ctx := context.Background()
		assert.Error(t, ForField(ctx, "test", "test value"))
	})

	t.Run("empty warning on context", func(t *testing.T) {
		ctx := newContext(context.Background())
		newW, ok := ctx.Value(warnerContextkey).(*warner)
		assert.True(t, ok)
		assert.Empty(t, newW)
	})
}

func TestForField(t *testing.T) {
	ctx := newContext(context.Background())
	assert.NoError(t, ForField(ctx, "test_field", "this is a test"))

	newW, ok := ctx.Value(warnerContextkey).(*warner)
	assert.True(t, ok)
	assert.Equal(t, &warner{fieldWarnings: []*pbwarnings.FieldWarning{
		{
			Name:    "test_field",
			Warning: "this is a test",
		},
	}}, newW)
}

func TestForAction(t *testing.T) {
	ctx := newContext(context.Background())
	assert.NoError(t, ForAction(ctx, "test_action", "this is a test"))

	newW, ok := ctx.Value(warnerContextkey).(*warner)
	assert.True(t, ok)
	assert.Equal(t, &warner{actionWarnings: []*pbwarnings.ActionWarning{
		{
			Name:    "test_action",
			Warning: "this is a test",
		},
	}}, newW)
}

func TestForBehavior(t *testing.T) {
	ctx := newContext(context.Background())
	assert.NoError(t, ForBehavior(ctx, "this is a test"))

	newW, ok := ctx.Value(warnerContextkey).(*warner)
	assert.True(t, ok)
	assert.Equal(t, &warner{behaviorWarnings: []*pbwarnings.BehaviorWarning{
		{
			Warning: "this is a test",
		},
	}}, newW)
}

func TestGrpcGatwayWiring(t *testing.T) {
	ctx := context.Background()
	fieldWarnings := []*pbwarnings.FieldWarning{
		{
			Name:    "test_field_1",
			Warning: "test warning description 1",
		},
		{
			Name:    "test_field_2",
			Warning: "test warning description 2",
		},
	}
	actionWarnings := []*pbwarnings.ActionWarning{
		{
			Name:    "test_action1",
			Warning: "test warning description 1",
		},
		{
			Name:    "test_action2",
			Warning: "test warning description 2",
		},
	}
	behaviorWarnings := []*pbwarnings.BehaviorWarning{
		{
			Warning: "test warning 1",
		},
		{
			Warning: "test warning 2",
		},
	}

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

	t.Run("field warning only", func(t *testing.T) {
		service.addWarnFunc = func(ctx context.Context) {
			for _, w := range fieldWarnings {
				assert.NoError(t, ForField(ctx, w.GetName(), w.GetWarning()))
			}
		}
		resp, err := http.Get(fmt.Sprintf("http://%s/health", lis.Addr().String()))
		require.NoError(t, err)
		got := resp.Header.Get(warningHeader)
		require.NoError(t, err)

		want, err := protojson.Marshal(&pbwarnings.Warning{
			RequestFields: fieldWarnings,
		})
		require.NoError(t, err)
		assert.Equal(t, string(want), got)
	})

	t.Run("action warning only", func(t *testing.T) {
		service.addWarnFunc = func(ctx context.Context) {
			for _, w := range actionWarnings {
				assert.NoError(t, ForAction(ctx, w.GetName(), w.GetWarning()))
			}
		}
		resp, err := http.Get(fmt.Sprintf("http://%s/health", lis.Addr().String()))
		require.NoError(t, err)
		got := resp.Header.Get(warningHeader)
		require.NoError(t, err)

		want, err := protojson.Marshal(&pbwarnings.Warning{
			Actions: actionWarnings,
		})
		require.NoError(t, err)
		assert.Equal(t, string(want), got)
	})

	t.Run("behavior warning only", func(t *testing.T) {
		service.addWarnFunc = func(ctx context.Context) {
			for _, w := range behaviorWarnings {
				assert.NoError(t, ForBehavior(ctx, w.GetWarning()))
			}
		}
		resp, err := http.Get(fmt.Sprintf("http://%s/health", lis.Addr().String()))
		require.NoError(t, err)
		got := resp.Header.Get(warningHeader)
		require.NoError(t, err)

		want, err := protojson.Marshal(&pbwarnings.Warning{
			Behaviors: behaviorWarnings,
		})
		require.NoError(t, err)
		assert.Equal(t, string(want), got)
	})
	t.Run("all warning types", func(t *testing.T) {

		service.addWarnFunc = func(ctx context.Context) {
			for _, w := range fieldWarnings {
				assert.NoError(t, ForField(ctx, w.GetName(), w.GetWarning()))
			}
			for _, w := range actionWarnings {
				assert.NoError(t, ForAction(ctx, w.GetName(), w.GetWarning()))
			}
			for _, w := range behaviorWarnings {
				assert.NoError(t, ForBehavior(ctx, w.GetWarning()))
			}
		}
		resp, err := http.Get(fmt.Sprintf("http://%s/health", lis.Addr().String()))
		require.NoError(t, err)
		got := resp.Header.Get(warningHeader)
		require.NoError(t, err)

		want, err := protojson.Marshal(&pbwarnings.Warning{
			RequestFields: fieldWarnings,
			Actions:       actionWarnings,
			Behaviors:     behaviorWarnings,
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
