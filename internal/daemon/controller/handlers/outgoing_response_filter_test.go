// Copyright IBM Corp. 2020, 2026
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
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 2)

	byName := make(map[string]*http.Cookie, len(cookies))
	for _, c := range cookies {
		byName[c.Name] = c
	}

	httpOnlyCookie, ok := byName[HttpOnlyCookieName]
	require.True(t, ok)
	assert.Equal(t, "34567890", httpOnlyCookie.Value)
	assert.Equal(t, "/", httpOnlyCookie.Path)
	assert.True(t, httpOnlyCookie.HttpOnly)
	assert.True(t, httpOnlyCookie.Secure)

	jsVisibleCookie, ok := byName[JsVisibleCookieName]
	require.True(t, ok)
	assert.Equal(t, "t_abc_12", jsVisibleCookie.Value)
	assert.Equal(t, "/", jsVisibleCookie.Path)
	assert.False(t, jsVisibleCookie.HttpOnly)
	assert.True(t, jsVisibleCookie.Secure)
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
