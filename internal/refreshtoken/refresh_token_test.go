// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package refreshtoken_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
)

func Test_ValidateRefreshToken(t *testing.T) {
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	tests := []struct {
		name          string
		token         *refreshtoken.Token
		grantsHash    []byte
		resourceType  resource.Type
		wantErrString string
		wantErrCode   errors.Code
	}{
		{
			name: "valid token",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Session,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:   []byte("some hash"),
			resourceType: resource.Session,
		},
		{
			name:          "nil token",
			token:         nil,
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Session,
			wantErrString: "refresh token was missing",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "no permissions hash",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Session,
				GrantsHash:          nil,
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Session,
			wantErrString: "refresh token was missing its permission hash",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "changed permissions hash",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Session,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some other hash"),
			resourceType:  resource.Session,
			wantErrString: "grants have changed since refresh token was issued",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "created in the future",
			token: &refreshtoken.Token{
				CreatedTime:         time.Now().AddDate(1, 0, 0),
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Session,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Session,
			wantErrString: "refresh token was created in the future",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "expired",
			token: &refreshtoken.Token{
				CreatedTime:         time.Now().AddDate(0, 0, -31),
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Session,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Session,
			wantErrString: "refresh token was expired",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "updated before created",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, -1),
				ResourceType:        resource.Session,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Session,
			wantErrString: "refresh token was updated before its creation time",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "updated after now",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         time.Now().AddDate(0, 0, 1),
				ResourceType:        resource.Session,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Session,
			wantErrString: "refresh token was updated in the future",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "resource type mismatch",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Session,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.SessionRecording,
			wantErrString: "refresh token resource type does not match expected resource type",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "last item ID unset",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Session,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Session,
			wantErrString: "refresh token missing last item ID",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "last item ID unset",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Session,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Session,
			wantErrString: "refresh token missing last item ID",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "updated in the future",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Session,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: time.Now().AddDate(1, 0, 0),
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Session,
			wantErrString: "refresh token last item was updated in the future",
			wantErrCode:   errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.token.Validate(context.Background(), tt.resourceType, tt.grantsHash)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
		})
	}
}
