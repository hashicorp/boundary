// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pagination

import (
	"bytes"
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

// ParseRefreshToken parses a refresh token from the input, returning
// an error if the parsing fails.
func ParseRefreshToken(ctx context.Context, token string) (*pbs.ListRefreshToken, error) {
	const op = "list.ParseRefreshToken"
	marshaled, err := base58.Decode(token)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var tok pbs.ListRefreshToken
	if err := proto.Unmarshal(marshaled, &tok); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &tok, nil
}

// MarshalRefreshToken marshals a refresh token to its string representation.
func MarshalRefreshToken(ctx context.Context, token *pbs.ListRefreshToken) (string, error) {
	const op = "list.MarshalRefreshToken"
	if token == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "token is required")
	}
	marshaled, err := proto.Marshal(token)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return base58.Encode(marshaled), nil
}

// ValidateRefreshToken validates the refresh token against the inputs
// and the current time.
func ValidateRefreshToken(ctx context.Context, token *pbs.ListRefreshToken, grantsHash []byte, resourceType pbs.ResourceType) error {
	const op = "list.ValidateRefreshToken"
	if token == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was nil")
	}
	if len(token.GetPermissionsHash()) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was missing its permission hash")
	}
	if !bytes.Equal(token.GetPermissionsHash(), grantsHash) {
		return errors.New(ctx, errors.InvalidParameter, op, "permissions have changed since refresh token was issued")
	}
	if !token.GetCreatedTime().IsValid() {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token missing create time")
	}
	if token.GetCreatedTime().AsTime().After(time.Now()) {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was created in the future")
	}
	// Tokens older than 30 days have expired
	if token.GetCreatedTime().AsTime().Before(time.Now().AddDate(0, 0, -30)) {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was expired")
	}
	if token.GetResourceType() != resourceType {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was not created for this resource type")
	}
	if token.GetLastItemId() == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token missing last item ID")
	}
	if !token.GetLastItemUpdatedTime().IsValid() {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token missing last item updated time")
	}
	if token.GetLastItemUpdatedTime().AsTime().After(time.Now()) {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token last item was updated in the future")
	}
	return nil
}
