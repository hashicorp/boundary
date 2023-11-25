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
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_ParseListToken(t *testing.T) {
	t.Parallel()
	pagToken := &pbs.ListToken{
		CreateTime:   timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
		ResourceType: pbs.ResourceType_RESOURCE_TYPE_TARGET,
		GrantsHash:   []byte("some hash"),
		Token: &pbs.ListToken_PaginationToken{
			PaginationToken: &pbs.PaginationToken{
				LastItemId:         "ttcp_1234567890",
				LastItemCreateTime: timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
	}
	pagBytes, err := proto.Marshal(pagToken)
	require.NoError(t, err)
	pagString := base58.Encode(pagBytes)

	srToken := &pbs.ListToken{
		CreateTime:   timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
		ResourceType: pbs.ResourceType_RESOURCE_TYPE_TARGET,
		GrantsHash:   []byte("some hash"),
		Token: &pbs.ListToken_StartRefreshToken{
			StartRefreshToken: &pbs.StartRefreshToken{
				PreviousPhaseUpperBound: timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
				PreviousDeletedIdsTime:  timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
	}
	srBytes, err := proto.Marshal(srToken)
	require.NoError(t, err)
	srString := base58.Encode(srBytes)

	rToken := &pbs.ListToken{
		CreateTime:   timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
		ResourceType: pbs.ResourceType_RESOURCE_TYPE_TARGET,
		GrantsHash:   []byte("some hash"),
		Token: &pbs.ListToken_RefreshToken{
			RefreshToken: &pbs.RefreshToken{
				PhaseUpperBound:        timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
				PhaseLowerBound:        timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
				PreviousDeletedIdsTime: timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
				LastItemId:             "ttcp_1234567890",
				LastItemUpdateTime:     timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
	}
	rBytes, err := proto.Marshal(rToken)
	require.NoError(t, err)
	rString := base58.Encode(rBytes)

	tests := []struct {
		name    string
		token   string
		want    *pbs.ListToken
		wantErr bool
	}{
		{
			name:  "valid pagination",
			token: pagString,
			want:  pagToken,
		},
		{
			name:  "valid start-refresh",
			token: srString,
			want:  srToken,
		},
		{
			name:  "valid refresh",
			token: rString,
			want:  rToken,
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
			got, err := handlers.ParseListToken(context.Background(), tt.token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}

func Test_MarshalListToken(t *testing.T) {
	t.Parallel()
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	tokenCreateTime := fiveDaysAgo
	lastItemCreateTime := fiveDaysAgo.Add(time.Hour)
	lastItemUpdateTime := fiveDaysAgo.Add(2 * time.Hour)
	previousPhaseUpperBoundTime := fiveDaysAgo.Add(3 * time.Hour)
	previousDeletedIdsTime := fiveDaysAgo.Add(4 * time.Hour)
	phaseLowerBound := fiveDaysAgo.Add(5 * time.Hour)
	phaseUpperBound := fiveDaysAgo.Add(6 * time.Hour)

	t.Run("valid pagination", func(t *testing.T) {
		pagToken := &pbs.ListToken{
			CreateTime:   timestamppb.New(tokenCreateTime),
			ResourceType: pbs.ResourceType_RESOURCE_TYPE_TARGET,
			GrantsHash:   []byte("some hash"),
			Token: &pbs.ListToken_PaginationToken{
				PaginationToken: &pbs.PaginationToken{
					LastItemId:         "ttcp_1234567890",
					LastItemCreateTime: timestamppb.New(lastItemCreateTime),
				},
			},
		}
		pagBytes, err := proto.Marshal(pagToken)
		require.NoError(t, err)
		pagString := base58.Encode(pagBytes)
		domainPagToken, err := listtoken.NewPagination(
			context.Background(),
			pagToken.CreateTime.AsTime(),
			handlers.ListTokenResourceToResource(pagToken.ResourceType),
			pagToken.GrantsHash,
			pagToken.GetPaginationToken().LastItemId,
			pagToken.GetPaginationToken().LastItemCreateTime.AsTime(),
		)
		require.NoError(t, err)

		got, err := handlers.MarshalListToken(context.Background(), domainPagToken, pbs.ResourceType_RESOURCE_TYPE_TARGET)
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(got, pagString, protocmp.Transform()))
	})
	t.Run("valid start-refresh", func(t *testing.T) {
		srToken := &pbs.ListToken{
			CreateTime:   timestamppb.New(tokenCreateTime),
			ResourceType: pbs.ResourceType_RESOURCE_TYPE_TARGET,
			GrantsHash:   []byte("some hash"),
			Token: &pbs.ListToken_StartRefreshToken{
				StartRefreshToken: &pbs.StartRefreshToken{
					PreviousPhaseUpperBound: timestamppb.New(previousPhaseUpperBoundTime),
					PreviousDeletedIdsTime:  timestamppb.New(previousDeletedIdsTime),
				},
			},
		}
		srBytes, err := proto.Marshal(srToken)
		require.NoError(t, err)
		srString := base58.Encode(srBytes)
		domainSrToken, err := listtoken.NewStartRefresh(
			context.Background(),
			srToken.CreateTime.AsTime(),
			handlers.ListTokenResourceToResource(srToken.ResourceType),
			srToken.GrantsHash,
			srToken.GetStartRefreshToken().PreviousDeletedIdsTime.AsTime(),
			srToken.GetStartRefreshToken().PreviousPhaseUpperBound.AsTime(),
		)
		require.NoError(t, err)

		got, err := handlers.MarshalListToken(context.Background(), domainSrToken, pbs.ResourceType_RESOURCE_TYPE_TARGET)
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(got, srString, protocmp.Transform()))
	})
	t.Run("valid refresh", func(t *testing.T) {
		rToken := &pbs.ListToken{
			CreateTime:   timestamppb.New(tokenCreateTime),
			ResourceType: pbs.ResourceType_RESOURCE_TYPE_TARGET,
			GrantsHash:   []byte("some hash"),
			Token: &pbs.ListToken_RefreshToken{
				RefreshToken: &pbs.RefreshToken{
					PhaseUpperBound:        timestamppb.New(phaseUpperBound),
					PhaseLowerBound:        timestamppb.New(phaseLowerBound),
					PreviousDeletedIdsTime: timestamppb.New(previousDeletedIdsTime),
					LastItemId:             "ttcp_1234567890",
					LastItemUpdateTime:     timestamppb.New(lastItemUpdateTime),
				},
			},
		}
		rBytes, err := proto.Marshal(rToken)
		require.NoError(t, err)
		rString := base58.Encode(rBytes)
		domainRToken, err := listtoken.NewRefresh(
			context.Background(),
			tokenCreateTime,
			handlers.ListTokenResourceToResource(rToken.ResourceType),
			rToken.GrantsHash,
			rToken.GetRefreshToken().PreviousDeletedIdsTime.AsTime(),
			rToken.GetRefreshToken().PhaseUpperBound.AsTime(),
			rToken.GetRefreshToken().PhaseLowerBound.AsTime(),
			rToken.GetRefreshToken().LastItemId,
			rToken.GetRefreshToken().LastItemUpdateTime.AsTime(),
		)
		require.NoError(t, err)

		got, err := handlers.MarshalListToken(context.Background(), domainRToken, pbs.ResourceType_RESOURCE_TYPE_TARGET)
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(got, rString, protocmp.Transform()))
	})
	t.Run("nil token", func(t *testing.T) {
		_, err := handlers.MarshalListToken(context.Background(), nil, pbs.ResourceType_RESOURCE_TYPE_TARGET)
		require.Error(t, err)
	})
	t.Run("invalid token resource type", func(t *testing.T) {
		domainPagToken, err := listtoken.NewPagination(
			context.Background(),
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"ttcp_1234567890",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		_, err = handlers.MarshalListToken(context.Background(), domainPagToken, pbs.ResourceType_RESOURCE_TYPE_UNSPECIFIED)
		require.Error(t, err)
	})
	t.Run("token resource type mismatch", func(t *testing.T) {
		domainPagToken, err := listtoken.NewPagination(
			context.Background(),
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"ttcp_1234567890",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		_, err = handlers.MarshalListToken(context.Background(), domainPagToken, pbs.ResourceType_RESOURCE_TYPE_SESSION)
		require.Error(t, err)
	})
	t.Run("invalid token subtype", func(t *testing.T) {
		invalidToken := &listtoken.Token{
			CreateTime:   tokenCreateTime,
			ResourceType: resource.Target,
			GrantsHash:   []byte("some hash"),
		}
		_, err := handlers.MarshalListToken(context.Background(), invalidToken, pbs.ResourceType_RESOURCE_TYPE_TARGET)
		require.Error(t, err)
	})
}

func TestListTokenResourceToResource(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rt   pbs.ResourceType
		want resource.Type
	}{
		{
			name: "default unknown",
			rt:   0,
			want: resource.Unknown,
		},
		{
			name: "account",
			rt:   pbs.ResourceType_RESOURCE_TYPE_ACCOUNT,
			want: resource.Account,
		},
		{
			name: "auth_method",
			rt:   pbs.ResourceType_RESOURCE_TYPE_AUTH_METHOD,
			want: resource.AuthMethod,
		},
		{
			name: "auth_token",
			rt:   pbs.ResourceType_RESOURCE_TYPE_AUTH_TOKEN,
			want: resource.AuthToken,
		},
		{
			name: "credential_library",
			rt:   pbs.ResourceType_RESOURCE_TYPE_CREDENTIAL_LIBRARY,
			want: resource.CredentialLibrary,
		},
		{
			name: "credential_store",
			rt:   pbs.ResourceType_RESOURCE_TYPE_CREDENTIAL_STORE,
			want: resource.CredentialStore,
		},
		{
			name: "credential",
			rt:   pbs.ResourceType_RESOURCE_TYPE_CREDENTIAL,
			want: resource.Credential,
		},
		{
			name: "group",
			rt:   pbs.ResourceType_RESOURCE_TYPE_GROUP,
			want: resource.Group,
		},
		{
			name: "host_catalog",
			rt:   pbs.ResourceType_RESOURCE_TYPE_HOST_CATALOG,
			want: resource.HostCatalog,
		},
		{
			name: "host_set",
			rt:   pbs.ResourceType_RESOURCE_TYPE_HOST_SET,
			want: resource.HostSet,
		},
		{
			name: "host",
			rt:   pbs.ResourceType_RESOURCE_TYPE_HOST,
			want: resource.Host,
		},
		{
			name: "managed_group",
			rt:   pbs.ResourceType_RESOURCE_TYPE_MANAGED_GROUP,
			want: resource.ManagedGroup,
		},
		{
			name: "role",
			rt:   pbs.ResourceType_RESOURCE_TYPE_ROLE,
			want: resource.Role,
		},
		{
			name: "scope",
			rt:   pbs.ResourceType_RESOURCE_TYPE_SCOPE,
			want: resource.Scope,
		},
		{
			name: "session_recording",
			rt:   pbs.ResourceType_RESOURCE_TYPE_SESSION_RECORDING,
			want: resource.SessionRecording,
		},
		{
			name: "session",
			rt:   pbs.ResourceType_RESOURCE_TYPE_SESSION,
			want: resource.Session,
		},
		{
			name: "storage_bucket",
			rt:   pbs.ResourceType_RESOURCE_TYPE_STORAGE_BUCKET,
			want: resource.StorageBucket,
		},
		{
			name: "target",
			rt:   pbs.ResourceType_RESOURCE_TYPE_TARGET,
			want: resource.Target,
		},
		{
			name: "user",
			rt:   pbs.ResourceType_RESOURCE_TYPE_USER,
			want: resource.User,
		},
		{
			name: "worker",
			rt:   pbs.ResourceType_RESOURCE_TYPE_WORKER,
			want: resource.Worker,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := handlers.ListTokenResourceToResource(tt.rt)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}
