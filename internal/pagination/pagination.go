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

// FillPage repeatedly calls listItemsFn until it has gathered pageSize number of items,
// subject to the convertAndFilterFunc, or until there are no more results.
// It reports whether it reached the end of iteration.
func FillPage[T any | *any, PbT any](
	ctx context.Context,
	limit int,
	pageSize int,
	listItemsFn func(prevPageLast T) ([]T, error),
	convertAndFilterFn func(item T) (*PbT, error),
) ([]*PbT, bool, error) {
	const op = "pagination.FillPage"

	// Empty will be a nil pointer for pointer types of
	// T, and a nil interface for interface types.
	var empty T
	page, err := listItemsFn(empty)
	if err != nil {
		return nil, false, errors.Wrap(ctx, err, op)
	}
	finalItems := make([]*PbT, 0, pageSize)
	// If we got fewer results than requested, we're at the end.
	completeListing := len(page) < limit
	if len(page) > pageSize {
		// Don't loop over the extra item
		// we requested to see if we were at the end
		page = page[:pageSize]
	}
	// Loop until we've filled the page
dbLoop:
	for {
		for i, item := range page {
			pbItem, err := convertAndFilterFn(item)
			if err != nil {
				return nil, false, errors.Wrap(ctx, err, op)
			}
			if pbItem != nil {
				finalItems = append(finalItems, pbItem)
				if len(finalItems) == pageSize {
					if completeListing && i != len(page)-1 {
						completeListing = false
					}
					break dbLoop
				}
			}
		}
		if completeListing {
			// No need to make more requests
			break dbLoop
		}

		lastItem := page[len(page)-1]
		// Request another result set from the DB until we fill the page
		page, err = listItemsFn(lastItem)
		if err != nil {
			return nil, false, errors.Wrap(ctx, err, op)
		}
		// If we got fewer results than requested, we're at the end.
		completeListing = len(page) < limit
		if len(page) > pageSize {
			// Don't loop over the extra item
			// we requested to see if we were at the end
			page = page[:pageSize]
		}
	}

	return finalItems, completeListing, nil
}
