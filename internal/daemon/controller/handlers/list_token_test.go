// Copyright IBM Corp. 2020, 2025
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
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	tokenCreateTime := fiveDaysAgo
	lastItemCreateTime := fiveDaysAgo.Add(-2 * time.Hour)
	lastItemUpdateTime := fiveDaysAgo.Add(-time.Hour)
	previousPhaseUpperBoundTime := fiveDaysAgo.Add(4 * time.Hour)
	previousDeletedIdsTime := fiveDaysAgo.Add(3 * time.Hour)
	phaseLowerBound := fiveDaysAgo.Add(time.Hour)
	phaseUpperBound := fiveDaysAgo.Add(2 * time.Hour)

	t.Run("valid pagination", func(t *testing.T) {
		t.Parallel()
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

		got, err := handlers.ParseListToken(context.Background(), pagString, resource.Target, []byte("some hash"))
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(got, domainPagToken, protocmp.Transform()))
	})
	t.Run("valid start-refresh", func(t *testing.T) {
		t.Parallel()
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

		got, err := handlers.ParseListToken(context.Background(), srString, resource.Target, []byte("some hash"))
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(got, domainSrToken, protocmp.Transform()))
	})
	t.Run("valid refresh", func(t *testing.T) {
		t.Parallel()
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

		got, err := handlers.ParseListToken(context.Background(), rString, resource.Target, []byte("some hash"))
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(got, domainRToken, protocmp.Transform()))
	})
	t.Run("empty token", func(t *testing.T) {
		t.Parallel()
		_, err := handlers.ParseListToken(context.Background(), "", resource.Target, []byte("some hash"))
		require.Error(t, err)
	})
	t.Run("invalid base58", func(t *testing.T) {
		t.Parallel()
		_, err := handlers.ParseListToken(context.Background(), "not a token", resource.Target, []byte("some hash"))
		require.Error(t, err)
	})
	t.Run("invalid proto", func(t *testing.T) {
		t.Parallel()
		_, err := handlers.ParseListToken(context.Background(), base58.Encode([]byte("not a token")), resource.Target, []byte("some hash"))
		require.Error(t, err)
	})
	t.Run("resource type mismatch", func(t *testing.T) {
		t.Parallel()
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

		_, err = handlers.ParseListToken(context.Background(), pagString, resource.Session, []byte("some hash"))
		require.Error(t, err)
	})
	t.Run("grants hash mismatch", func(t *testing.T) {
		t.Parallel()
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

		_, err = handlers.ParseListToken(context.Background(), pagString, resource.Target, []byte("some other hash"))
		require.Error(t, err)
	})
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
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
		_, err := handlers.MarshalListToken(context.Background(), nil, pbs.ResourceType_RESOURCE_TYPE_TARGET)
		require.Error(t, err)
	})
	t.Run("invalid token resource type", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
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
			name: "alias",
			rt:   pbs.ResourceType_RESOURCE_TYPE_ALIAS,
			want: resource.Alias,
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
		{
			name: "policy",
			rt:   pbs.ResourceType_RESOURCE_TYPE_POLICY,
			want: resource.Policy,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := handlers.ListTokenResourceToResource(tt.rt)
			require.Empty(t, cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}
