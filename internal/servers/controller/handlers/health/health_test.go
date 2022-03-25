package health

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/gen/controller/ops/services"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestGetHealth(t *testing.T) {
	tests := []struct {
		name                 string
		ctx                  context.Context
		serviceUnavailable   bool
		expGetHealthResponse *services.GetHealthResponse
		expErr               bool
		expErrMsg            string
	}{
		{
			name:                 "healthy reply",
			ctx:                  context.Background(),
			serviceUnavailable:   false,
			expGetHealthResponse: &services.GetHealthResponse{},
			expErr:               false,
		},
		{
			name:                 "service unavailable reply",
			ctx:                  grpc.NewContextWithServerTransportStream(context.Background(), &testServerTransportStream{expHttpCode: "503"}),
			serviceUnavailable:   true,
			expGetHealthResponse: &services.GetHealthResponse{},
			expErr:               false,
		},
		{
			name:               "get health error",
			ctx:                context.Background(),
			serviceUnavailable: true,
			expErr:             true,
			expErrMsg:          "handlers.SetHttpStatusCode: internal error, unknown: error #500: rpc error: code = Internal desc = grpc: failed to fetch the stream from the context context.Background",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewService()

			if tt.serviceUnavailable {
				hs.StartServiceUnavailableReplies()
			}

			rsp, err := hs.GetHealth(tt.ctx, &services.GetHealthRequest{})
			if tt.expErr {
				require.Error(t, err)
				require.EqualError(t, err, tt.expErrMsg)
				return
			}

			require.NoError(t, err)
			require.EqualValues(t, tt.expGetHealthResponse, rsp)
		})
	}
}

type testServerTransportStream struct {
	expHttpCode string
}

func (s *testServerTransportStream) Method() string                  { return "" }
func (s *testServerTransportStream) SendHeader(md metadata.MD) error { return nil }
func (s *testServerTransportStream) SetTrailer(md metadata.MD) error { return nil }
func (s *testServerTransportStream) SetHeader(md metadata.MD) error {
	codes, ok := md["x-http-code"]
	if !ok {
		return fmt.Errorf("x-http-code header not found")
	}
	if len(codes) != 1 {
		return fmt.Errorf("expected only one element in http codes, got %d", len(codes))
	}
	if codes[0] != s.expHttpCode {
		return fmt.Errorf("expected http code %q, got %q", s.expHttpCode, codes[0])
	}
	return nil
}
