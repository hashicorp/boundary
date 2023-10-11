// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package refreshtoken

import (
	"bytes"
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// A RefreshToken is returned in list endpoints for the purposes of pagination
type RefreshToken struct {
	CreatedTime         time.Time
	ResourceType        resource.Type
	GrantsHash          []byte
	LastItemId          string
	LastItemUpdatedTime time.Time
}

// ValidateRefreshToken validates a refresh token.
func (rt *RefreshToken) Validate(
	ctx context.Context,
	expectedResourceType resource.Type,
	expectedGrantsHash []byte,
) error {
	const op = "refreshtoken.ValidateRefreshToken"
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
