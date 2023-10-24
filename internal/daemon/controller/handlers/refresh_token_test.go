// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package handlers_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_ParseRefreshToken(t *testing.T) {
	testToken := &pbs.ListRefreshToken{
		CreatedTime:         timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
		ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
		GrantsHash:          []byte("some hash"),
		LastItemId:          "s_1234567890",
		LastItemUpdatedTime: timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
	}
	tokBytes, err := proto.Marshal(testToken)
	require.NoError(t, err)
	tokString := base58.Encode(tokBytes)

	tests := []struct {
		name    string
		token   string
		want    *pbs.ListRefreshToken
		wantErr bool
	}{
		{
			name:  "valid",
			token: tokString,
			want:  testToken,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "invalid base58",
			token:   "not a token",
			wantErr: true,
		},
		{
			name:    "invalid proto",
			token:   base58.Encode([]byte("not a token")),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := handlers.ParseRefreshToken(context.Background(), tt.token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}

func Test_MarshalRefreshToken(t *testing.T) {
	testToken := &pbs.ListRefreshToken{
		CreatedTime:         timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
		ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
		GrantsHash:          []byte("some hash"),
		LastItemId:          "s_1234567890",
		LastItemUpdatedTime: timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
	}
	tokBytes, err := proto.Marshal(testToken)
	require.NoError(t, err)
	tokString := base58.Encode(tokBytes)

	tests := []struct {
		name    string
		token   *pbs.ListRefreshToken
		want    string
		wantErr bool
	}{
		{
			name:  "valid",
			token: testToken,
			want:  tokString,
		},
		{
			name:    "nil token",
			token:   nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := handlers.MarshalRefreshToken(context.Background(), tt.token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}

func TestRefreshTokenResourceToResource(t *testing.T) {
	tests := []struct {
		name string
		rt   pbs.ResourceType
		want resource.Type
	}{
		{
			name: "valid known",
			rt:   pbs.ResourceType_RESOURCE_TYPE_TARGET,
			want: resource.Target,
		},
		{
			name: "default unknown",
			rt:   0,
			want: resource.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := handlers.RefreshTokenResourceToResource(tt.rt)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}
