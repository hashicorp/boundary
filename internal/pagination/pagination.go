// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pagination

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

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

func MarshalRefreshToken(ctx context.Context, token *pbs.ListRefreshToken) (string, error) {
	const op = "list.MarshalRefreshToken"
	marshaled, err := proto.Marshal(token)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return base58.Encode(marshaled), nil
}

func ValidateRefreshToken(ctx context.Context, token *pbs.ListRefreshToken, grantsHash []byte, resourceType pbs.ResourceType) error {
	const op = "list.ValidateRefreshToken"
	if token == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was nil")
	}
	if !bytes.Equal(token.GetPermissionsHash(), grantsHash) {
		return errors.New(ctx, errors.InvalidParameter, op, "permissions have changed since refresh token was issued")
	}
	if token.CreatedTime.AsTime().After(time.Now()) {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was created in the future")
	}
	if token.GetResourceType() != resourceType {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("refresh token was not created for this resource type, got %q, wanted %q", token.GetResourceType(), resourceType))
	}
	if token.GetLastItemId() == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token missing last item ID")
	}
	if token.GetLastItemUpdateTime() == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token missing last item updated time")
	}
	if token.GetLastItemUpdateTime().AsTime().After(time.Now()) {
		return errors.New(ctx, errors.InvalidParameter, op, "refresh token was created in the future")
	}
	return nil
}
