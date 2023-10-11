// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package refreshtoken

import (
	"bytes"
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// A Token is returned in list endpoints for the purposes of pagination
type Token struct {
	CreatedTime         time.Time
	UpdatedTime         time.Time
	ResourceType        resource.Type
	GrantsHash          []byte
	LastItemId          string
	LastItemUpdatedTime time.Time
}

// New creates a new refresh token from a resource and grants hash
func New(res boundary.Resource, grantsHash []byte) *Token {
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

// Refresh refreshes a token's updated time
func (rt *Token) Refresh(updatedTime time.Time) *Token {
	rt.UpdatedTime = updatedTime
	return rt
}

// RefreshLastItem refreshes a token's updated time and last item
func (rt *Token) RefreshLastItem(res boundary.Resource, updatedTime time.Time) *Token {
	rt.UpdatedTime = updatedTime
	rt.LastItemId = res.GetPublicId()
	rt.LastItemUpdatedTime = res.GetUpdateTime().AsTime()
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
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was missing its permission hash")
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
