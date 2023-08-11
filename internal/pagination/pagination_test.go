// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pagination_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestParseRefreshToken(t *testing.T) {
	testToken := &pbs.ListRefreshToken{
		CreatedTime:         timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
		ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
		PermissionsHash:     []byte("some hash"),
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
			got, err := pagination.ParseRefreshToken(context.Background(), tt.token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}

func TestMarshalRefreshToken(t *testing.T) {
	testToken := &pbs.ListRefreshToken{
		CreatedTime:         timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
		ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
		PermissionsHash:     []byte("some hash"),
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
			got, err := pagination.MarshalRefreshToken(context.Background(), tt.token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}

func TestValidateRefreshToken(t *testing.T) {
	oldTime := timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC))
	tests := []struct {
		name          string
		token         *pbs.ListRefreshToken
		grantsHash    []byte
		resourceType  pbs.ResourceType
		wantErrString string
		wantErrCode   errors.Code
	}{
		{
			name: "valid token",
			token: &pbs.ListRefreshToken{
				CreatedTime:         oldTime,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: oldTime,
			},
			grantsHash:   []byte("some hash"),
			resourceType: pbs.ResourceType_RESOURCE_TYPE_SESSION,
		},
		{
			name:          "nil token",
			token:         nil,
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token was nil",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "no permissions hash",
			token: &pbs.ListRefreshToken{
				CreatedTime:         oldTime,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     nil,
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: oldTime,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token was missing its permission hash",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "changed permissions hash",
			token: &pbs.ListRefreshToken{
				CreatedTime:         oldTime,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: oldTime,
			},
			grantsHash:    []byte("some other hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "permissions have changed since refresh token was issued",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "invalid create time",
			token: &pbs.ListRefreshToken{
				CreatedTime:         nil,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: oldTime,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token missing create time",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "created in the future",
			token: &pbs.ListRefreshToken{
				CreatedTime:         timestamppb.New(time.Now().AddDate(1, 0, 0)),
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: oldTime,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token was created in the future",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "resource type mismatch",
			token: &pbs.ListRefreshToken{
				CreatedTime:         oldTime,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: oldTime,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION_RECORDING,
			wantErrString: "refresh token was not created for this resource type",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "last item ID unset",
			token: &pbs.ListRefreshToken{
				CreatedTime:         oldTime,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "",
				LastItemUpdatedTime: oldTime,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token missing last item ID",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "last item ID unset",
			token: &pbs.ListRefreshToken{
				CreatedTime:         oldTime,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "",
				LastItemUpdatedTime: oldTime,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token missing last item ID",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "invalid update time",
			token: &pbs.ListRefreshToken{
				CreatedTime:         oldTime,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: nil,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token missing last item updated time",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "updated in the future",
			token: &pbs.ListRefreshToken{
				CreatedTime:         oldTime,
				ResourceType:        pbs.ResourceType_RESOURCE_TYPE_SESSION,
				PermissionsHash:     []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: timestamppb.New(time.Now().AddDate(1, 0, 0)),
			},
			grantsHash:    []byte("some hash"),
			resourceType:  pbs.ResourceType_RESOURCE_TYPE_SESSION,
			wantErrString: "refresh token last item was updated in the future",
			wantErrCode:   errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pagination.ValidateRefreshToken(context.Background(), tt.token, tt.grantsHash, tt.resourceType)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
		})
	}
}
