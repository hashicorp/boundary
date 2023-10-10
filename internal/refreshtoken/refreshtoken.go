// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package refreshtoken

import (
	"bytes"
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
)

type ResourceType int

const (
	ResourceTypeUnknown ResourceType = iota
	ResourceTypeSession
	ResourceTypeTarget
)

// GrantsHasher defines the interface used
// to retrieve a hash of a users grants.
type GrantsHasher interface {
	GrantsHash(ctx context.Context) ([]byte, error)
}

// A RefreshToken is returned in list endpoints for the purposes of pagination
type RefreshToken struct {
	CreatedTime         time.Time
	ResourceType        ResourceType
	PermissionsHash     []byte
	LastItemId          string
	LastItemUpdatedTime time.Time
}

// ValidateRefreshToken validates a refresh token.
func ValidateRefreshToken(
	ctx context.Context,
	rt *RefreshToken,
	expectedResourceType ResourceType,
	grantsHasher GrantsHasher,
) error {
	const op = "refreshtoken.ValidateRefreshToken"
	if len(rt.PermissionsHash) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was missing its permission hash")
	}
	grantsHash, err := grantsHasher.GrantsHash(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if !bytes.Equal(rt.PermissionsHash, grantsHash) {
		return errors.New(ctx, errors.InvalidParameter, op, "permissions have changed since refresh token was issued")
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
