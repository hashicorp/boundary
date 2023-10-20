// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package refreshtoken_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db/timestamp"
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
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:   []byte("some hash"),
			resourceType: resource.Target,
		},
		{
			name:          "nil token",
			token:         nil,
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "refresh token was missing",
			wantErrCode:   errors.InvalidParameter,
		},
		{
			name: "no grants hash",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Target,
				GrantsHash:          nil,
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "refresh token was missing its grants hash",
			wantErrCode:   errors.InvalidRefreshToken,
		},
		{
			name: "changed grants hash",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some other hash"),
			resourceType:  resource.Target,
			wantErrString: "grants have changed since refresh token was issued",
			wantErrCode:   errors.InvalidRefreshToken,
		},
		{
			name: "created in the future",
			token: &refreshtoken.Token{
				CreatedTime:         time.Now().AddDate(1, 0, 0),
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "refresh token was created in the future",
			wantErrCode:   errors.InvalidRefreshToken,
		},
		{
			name: "expired",
			token: &refreshtoken.Token{
				CreatedTime:         time.Now().AddDate(0, 0, -31),
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "refresh token was expired",
			wantErrCode:   errors.InvalidRefreshToken,
		},
		{
			name: "updated before created",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, -1),
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "refresh token was updated before its creation time",
			wantErrCode:   errors.InvalidRefreshToken,
		},
		{
			name: "updated after now",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         time.Now().AddDate(0, 0, 1),
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "refresh token was updated in the future",
			wantErrCode:   errors.InvalidRefreshToken,
		},
		{
			name: "resource type mismatch",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.SessionRecording,
			wantErrString: "refresh token resource type does not match expected resource type",
			wantErrCode:   errors.InvalidRefreshToken,
		},
		{
			name: "last item ID unset",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "refresh token missing last item ID",
			wantErrCode:   errors.InvalidRefreshToken,
		},
		{
			name: "last item ID unset",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "",
				LastItemUpdatedTime: fiveDaysAgo,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "refresh token missing last item ID",
			wantErrCode:   errors.InvalidRefreshToken,
		},
		{
			name: "updated in the future",
			token: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "s_1234567890",
				LastItemUpdatedTime: time.Now().AddDate(1, 0, 0),
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "refresh token last item was updated in the future",
			wantErrCode:   errors.InvalidRefreshToken,
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

func TestNew(t *testing.T) {
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	tests := []struct {
		name                string
		createdTime         time.Time
		updatedTime         time.Time
		typ                 resource.Type
		grantsHash          []byte
		lastItemId          string
		lastItemUpdatedTime time.Time
		want                *refreshtoken.Token
		wantErrString       string
		wantErrCode         errors.Code
	}{
		{
			name:                "valid refresh token",
			createdTime:         fiveDaysAgo,
			updatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
			typ:                 resource.Target,
			grantsHash:          []byte("some hash"),
			lastItemId:          "some id",
			lastItemUpdatedTime: fiveDaysAgo,
			want: &refreshtoken.Token{
				CreatedTime:         fiveDaysAgo,
				UpdatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
				ResourceType:        resource.Target,
				GrantsHash:          []byte("some hash"),
				LastItemId:          "some id",
				LastItemUpdatedTime: fiveDaysAgo,
			},
		},
		{
			name:                "missing grants hash",
			createdTime:         fiveDaysAgo,
			updatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
			typ:                 resource.Target,
			grantsHash:          nil,
			lastItemId:          "some id",
			lastItemUpdatedTime: fiveDaysAgo,
			wantErrString:       "missing grants hash",
			wantErrCode:         errors.InvalidParameter,
		},
		{
			name:                "new created time",
			createdTime:         fiveDaysAgo.AddDate(1, 0, 0),
			updatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
			typ:                 resource.Target,
			grantsHash:          []byte("some hash"),
			lastItemId:          "some id",
			lastItemUpdatedTime: fiveDaysAgo,
			wantErrString:       "created time is in the future",
			wantErrCode:         errors.InvalidParameter,
		},
		{
			name:                "old created time",
			createdTime:         fiveDaysAgo.AddDate(-1, 0, 0),
			updatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
			typ:                 resource.Target,
			grantsHash:          []byte("some hash"),
			lastItemId:          "some id",
			lastItemUpdatedTime: fiveDaysAgo,
			wantErrString:       "created time is too old",
			wantErrCode:         errors.InvalidParameter,
		},
		{
			name:                "new updated time",
			createdTime:         fiveDaysAgo,
			updatedTime:         fiveDaysAgo.AddDate(1, 0, 0),
			typ:                 resource.Target,
			grantsHash:          []byte("some hash"),
			lastItemId:          "some id",
			lastItemUpdatedTime: fiveDaysAgo,
			wantErrString:       "updated time is in the future",
			wantErrCode:         errors.InvalidParameter,
		},
		{
			name:                "updated time older than created time",
			createdTime:         fiveDaysAgo,
			updatedTime:         fiveDaysAgo.AddDate(0, 0, -11),
			typ:                 resource.Target,
			grantsHash:          []byte("some hash"),
			lastItemId:          "some id",
			lastItemUpdatedTime: fiveDaysAgo,
			wantErrString:       "updated time is older than created time",
			wantErrCode:         errors.InvalidParameter,
		},
		{
			name:                "missing last item id",
			createdTime:         fiveDaysAgo,
			updatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
			typ:                 resource.Target,
			grantsHash:          []byte("some hash"),
			lastItemId:          "",
			lastItemUpdatedTime: fiveDaysAgo,
			wantErrString:       "missing last item ID",
			wantErrCode:         errors.InvalidParameter,
		},
		{
			name:                "new last item updated time",
			createdTime:         fiveDaysAgo,
			updatedTime:         fiveDaysAgo.AddDate(0, 0, 1),
			typ:                 resource.Target,
			grantsHash:          []byte("some hash"),
			lastItemId:          "some id",
			lastItemUpdatedTime: fiveDaysAgo.AddDate(1, 0, 0),
			wantErrString:       "last item updated time is in the future",
			wantErrCode:         errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := refreshtoken.New(context.Background(), tt.createdTime, tt.updatedTime, tt.typ, tt.grantsHash, tt.lastItemId, tt.lastItemUpdatedTime)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want))
		})
	}
}

type fakeTargetResource struct {
	boundary.Resource

	publicId   string
	updateTime *timestamp.Timestamp
}

func (m *fakeTargetResource) GetResourceType() resource.Type {
	return resource.Target
}

func (m *fakeTargetResource) GetPublicId() string {
	return m.publicId
}

func (m *fakeTargetResource) GetUpdateTime() *timestamp.Timestamp {
	return m.updateTime
}

func TestFromResource(t *testing.T) {
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	res := &fakeTargetResource{
		publicId:   "tcp_1234567890",
		updateTime: timestamp.New(fiveDaysAgo),
	}

	tok := refreshtoken.FromResource(res, []byte("some hash"))

	// Check that it's within 1 second of now according to the system
	// If this is flaky... just increase the limit 😬.
	require.True(t, tok.CreatedTime.Before(time.Now().Add(time.Second)))
	require.True(t, tok.CreatedTime.After(time.Now().Add(-time.Second)))
	require.True(t, tok.UpdatedTime.Before(time.Now().Add(time.Second)))
	require.True(t, tok.UpdatedTime.After(time.Now().Add(-time.Second)))

	require.Equal(t, tok.ResourceType, res.GetResourceType())
	require.Equal(t, tok.GrantsHash, []byte("some hash"))
	require.Equal(t, tok.LastItemId, res.GetPublicId())
	require.True(t, tok.LastItemUpdatedTime.Equal(res.GetUpdateTime().AsTime()))
}

func TestRefresh(t *testing.T) {
	createdTime := time.Now().AddDate(0, 0, -5)
	tok := &refreshtoken.Token{
		CreatedTime:         createdTime,
		UpdatedTime:         createdTime,
		ResourceType:        resource.Target,
		GrantsHash:          []byte("some hash"),
		LastItemId:          "tcp_1234567890",
		LastItemUpdatedTime: createdTime,
	}
	updatedTime := time.Now()
	newTok := tok.Refresh(updatedTime)

	require.True(t, newTok.UpdatedTime.Equal(updatedTime.Add(-refreshtoken.UpdatedTimeBuffer)))
	require.True(t, newTok.CreatedTime.Equal(createdTime))
	require.Equal(t, newTok.ResourceType, tok.ResourceType)
	require.Equal(t, newTok.GrantsHash, tok.GrantsHash)
	require.Equal(t, newTok.LastItemId, tok.LastItemId)
	require.True(t, newTok.LastItemUpdatedTime.Equal(tok.LastItemUpdatedTime))
}
