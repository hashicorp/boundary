// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// The refreshtoken package encapsulates domain logic surrounding
// list endpoint refresh tokens. Refresh tokens are used when users
// paginate through results in our list endpoints, and also to
// allow users to request new, updated and deleted resources.
package refreshtoken

import (
	"bytes"
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// UpdatedTimeBuffer is used to automatically adjust the updated
// time of a refresh token to account for delays between overalapping
// database transactions.
const UpdatedTimeBuffer = 30 * time.Second

// A Token is returned in list endpoints for the purposes of pagination
type Token struct {
	CreatedTime         time.Time
	UpdatedTime         time.Time
	ResourceType        resource.Type
	GrantsHash          []byte
	LastItemId          string
	LastItemUpdatedTime time.Time
}

// New creates a new refresh token from a createdTime, resource type, grants hash, and last item information
func New(ctx context.Context, createdTime time.Time, updatedTime time.Time, typ resource.Type, grantsHash []byte, lastItemId string, lastItemUpdatedTime time.Time) (*Token, error) {
	const op = "refreshtoken.New"

	if len(grantsHash) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if createdTime.After(time.Now()) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "created time is in the future")
	}
	if createdTime.Before(time.Now().AddDate(0, 0, -30)) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "created time is too old")
	}
	if updatedTime.Before(createdTime) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "updated time is older than created time")
	}
	if updatedTime.After(time.Now()) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "updated time is in the future")
	}
	if lastItemId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing last item ID")
	}
	if lastItemUpdatedTime.After(time.Now()) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "last item updated time is in the future")
	}

	return &Token{
		CreatedTime:         createdTime,
		UpdatedTime:         updatedTime,
		ResourceType:        typ,
		GrantsHash:          grantsHash,
		LastItemId:          lastItemId,
		LastItemUpdatedTime: lastItemUpdatedTime,
	}, nil
}

// FromResource creates a new refresh token from a resource and grants hash.
func FromResource(res boundary.Resource, grantsHash []byte) *Token {
	t := time.Now()
	return &Token{
		CreatedTime:         t,
		UpdatedTime:         t,
		ResourceType:        res.GetResourceType(),
		GrantsHash:          grantsHash,
		LastItemId:          res.GetPublicId(),
		LastItemUpdatedTime: res.GetUpdateTime().AsTime(),
	}
}

// LastItem returns the last item stored in the token.
func (rt *Token) LastItem() *item {
	return &item{
		publicId:     rt.LastItemId,
		updateTime:   rt.LastItemUpdatedTime,
		resourceType: rt.ResourceType,
	}
}

// Refresh refreshes a token's updated time. It accounts for overlapping
// database transactions by subtracting UpdatedTimeBuffer from the
// provided timestamp while ensuring that the updated time is never
// before the created time of the token.
func (rt *Token) Refresh(updatedTime time.Time) *Token {
	rt.UpdatedTime = updatedTime.Add(-UpdatedTimeBuffer)
	if rt.UpdatedTime.Before(rt.CreatedTime) {
		rt.UpdatedTime = rt.CreatedTime
	}
	return rt
}

// RefreshLastItem refreshes a token's updated time and last item.
// It accounts for overlapping database transactions by subtracting
// UpdatedTimeBuffer from the provided timestamp while ensuring that
// the updated time is never before the created time of the token.
func (rt *Token) RefreshLastItem(res boundary.Resource, updatedTime time.Time) *Token {
	rt.LastItemId = res.GetPublicId()
	rt.LastItemUpdatedTime = res.GetUpdateTime().AsTime()
	rt = rt.Refresh(updatedTime)
	return rt
}

// Validate validates the refresh token.
func (rt *Token) Validate(
	ctx context.Context,
	expectedResourceType resource.Type,
	expectedGrantsHash []byte,
) error {
	const op = "refreshtoken.Validate"
	if rt == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was missing")
	}
	if len(rt.GrantsHash) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was missing its grants hash")
	}
	if !bytes.Equal(rt.GrantsHash, expectedGrantsHash) {
		return errors.New(ctx, errors.InvalidParameter, op, "grants have changed since refresh token was issued")
	}
	if rt.CreatedTime.After(time.Now()) {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was created in the future")
	}
	// Tokens older than 30 days have expired
	if rt.CreatedTime.Before(time.Now().AddDate(0, 0, -30)) {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was expired")
	}
	if rt.UpdatedTime.Before(rt.CreatedTime) {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was updated before its creation time")
	}
	if rt.UpdatedTime.After(time.Now()) {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was updated in the future")
	}
	if rt.LastItemId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token missing last item ID")
	}
	if rt.LastItemUpdatedTime.After(time.Now()) {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token last item was updated in the future")
	}
	if rt.ResourceType != expectedResourceType {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token resource type does not match expected resource type")
	}

	return nil
}
