// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	emptypb "github.com/hashicorp/boundary/internal/gen/controller/api"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	pba "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

func TestOutgoingSplitCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	attrs, err := ProtoToStruct(context.Background(), &pba.AuthToken{Token: "t_abc_1234567890"})
	require.NoError(t, err)
	require.NoError(t, OutgoingResponseFilter(context.Background(), rec, &pbs.AuthenticateResponse{Attrs: &pbs.AuthenticateResponse_Attributes{Attributes: attrs}, Type: "cookie"}))
	assert.ElementsMatch(t, rec.Result().Cookies(), []*http.Cookie{
		{Name: HttpOnlyCookieName, Value: "34567890", HttpOnly: true, Path: "/", Raw: "wt-http-token-cookie=34567890; Path=/; HttpOnly"},
		{Name: JsVisibleCookieName, Value: "t_abc_12", Path: "/", Raw: "wt-js-token-cookie=t_abc_12; Path=/"},
	})
}

func TestOutgoingResponseFilter_StatusCode(t *testing.T) {
	tests := []struct {
		name           string
		md             runtime.ServerMetadata
		msg            proto.Message
		wantErr        bool
		wantStatusCode int
		wantContent    bool
	}{
		{
			name:           "204",
			md:             runtime.ServerMetadata{HeaderMD: metadata.Pairs(StatusCodeHeader, "204")},
			wantStatusCode: 204,
		},
		{
			name:           "418",
			md:             runtime.ServerMetadata{HeaderMD: metadata.Pairs(StatusCodeHeader, "418")},
			wantStatusCode: 418,
			wantContent:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rec := httptest.NewRecorder()
			ctx := runtime.NewServerMetadataContext(context.Background(), tt.md)
			err := OutgoingResponseFilter(ctx, rec, &emptypb.EmptyResponse{})
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			resp := rec.Result()
			if tt.wantStatusCode != 0 {
				assert.Equal(tt.wantStatusCode, resp.StatusCode)
			}
		})
	}
}
