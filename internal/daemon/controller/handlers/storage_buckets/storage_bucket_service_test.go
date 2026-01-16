// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package storage_buckets

import (
	"context"
	"testing"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	s := Service{}

	gotCreate, err := s.CreateStorageBucket(ctx, &pbs.CreateStorageBucketRequest{})
	require.Nil(gotCreate)
	require.Error(err)
	gotStatus, ok := status.FromError(err)
	require.True(ok)
	assert.Equal(gotStatus.Code(), codes.Unimplemented)
	assert.Equal(gotStatus.Message(), "storage buckets are an Enterprise-only feature")

	gotUpdate, err := s.UpdateStorageBucket(ctx, &pbs.UpdateStorageBucketRequest{})
	require.Nil(gotUpdate)
	require.Error(err)
	gotStatus, ok = status.FromError(err)
	require.True(ok)
	assert.Equal(gotStatus.Code(), codes.Unimplemented)
	assert.Equal(gotStatus.Message(), "storage buckets are an Enterprise-only feature")

	gotGet, err := s.GetStorageBucket(ctx, &pbs.GetStorageBucketRequest{})
	require.Nil(gotGet)
	require.Error(err)
	gotStatus, ok = status.FromError(err)
	require.True(ok)
	assert.Equal(gotStatus.Code(), codes.Unimplemented)
	assert.Equal(gotStatus.Message(), "storage buckets are an Enterprise-only feature")

	gotDelete, err := s.DeleteStorageBucket(ctx, &pbs.DeleteStorageBucketRequest{})
	require.Nil(gotDelete)
	require.Error(err)
	gotStatus, ok = status.FromError(err)
	require.True(ok)
	assert.Equal(gotStatus.Code(), codes.Unimplemented)
	assert.Equal(gotStatus.Message(), "storage buckets are an Enterprise-only feature")

	got, err := s.ListStorageBuckets(ctx, &pbs.ListStorageBucketsRequest{})
	require.Nil(got)
	require.Error(err)
	gotStatus, ok = status.FromError(err)
	require.True(ok)
	assert.Equal(gotStatus.Code(), codes.Unimplemented)
	assert.Equal(gotStatus.Message(), "storage buckets are an Enterprise-only feature")
}
