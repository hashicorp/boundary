// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package policies

import (
	"context"
	"testing"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPolicyService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	s := Service{}

	gotCreate, err := s.CreatePolicy(ctx, &pbs.CreatePolicyRequest{})
	require.Nil(gotCreate)
	require.Error(err)
	gotStatus, ok := status.FromError(err)
	require.True(ok)
	assert.Equal(gotStatus.Code(), codes.Unimplemented)
	assert.Equal(gotStatus.Message(), "Policies are an Enterprise-only feature")

	gotUpdate, err := s.UpdatePolicy(ctx, &pbs.UpdatePolicyRequest{})
	require.Nil(gotUpdate)
	require.Error(err)
	gotStatus, ok = status.FromError(err)
	require.True(ok)
	assert.Equal(gotStatus.Code(), codes.Unimplemented)
	assert.Equal(gotStatus.Message(), "Policies are an Enterprise-only feature")

	gotGet, err := s.GetPolicy(ctx, &pbs.GetPolicyRequest{})
	require.Nil(gotGet)
	require.Error(err)
	gotStatus, ok = status.FromError(err)
	require.True(ok)
	assert.Equal(gotStatus.Code(), codes.Unimplemented)
	assert.Equal(gotStatus.Message(), "Policies are an Enterprise-only feature")

	gotDelete, err := s.DeletePolicy(ctx, &pbs.DeletePolicyRequest{})
	require.Nil(gotDelete)
	require.Error(err)
	gotStatus, ok = status.FromError(err)
	require.True(ok)
	assert.Equal(gotStatus.Code(), codes.Unimplemented)
	assert.Equal(gotStatus.Message(), "Policies are an Enterprise-only feature")

	gotList, err := s.ListPolicies(ctx, &pbs.ListPoliciesRequest{})
	require.Nil(gotList)
	require.Error(err)
	gotStatus, ok = status.FromError(err)
	require.True(ok)
	assert.Equal(gotStatus.Code(), codes.Unimplemented)
	assert.Equal(gotStatus.Message(), "Policies are an Enterprise-only feature")
}
