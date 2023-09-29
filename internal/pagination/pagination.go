// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pagination

import (
	"bytes"
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ListRequest represents the incoming protobuf request type.
type ListRequest interface {
	GetPageSize() uint32
	GetRefreshToken() string
}

// ResponseItem represents the outgoing protobuf response type.
type ResponseItem interface {
	comparable
	GetId() string
	GetUpdatedTime() *timestamppb.Timestamp
}

// Repository defines the interface used to get
// extra metadata about the items in the DB.
type Repository interface {
	ListDeletedIds(ctx context.Context, since time.Time) ([]string, error)
	EstimatedCount(ctx context.Context) (int, error)
	Now(ctx context.Context) (time.Time, error)
}

// GrantsHasher defines the interface used
// to retrieve a hash of a users grants.
type GrantsHasher interface {
	GrantsHash(ctx context.Context) ([]byte, error)
}

// ListResponse represents the response from the paginated list operation.
type ListResponse[PbT ResponseItem] struct {
	Items                 []PbT
	CompleteListing       bool
	MarshaledRefreshToken string
	DeletedIds            []string
	EstimatedItemCount    int
}

// ListItemsFunc defines the signature of the callback used to list
// items for a specific resource type.
type ListItemsFunc[T any] func(prevPageLast T, refreshToken *pbs.ListRefreshToken, limit int) ([]T, error)

// ConvertAndFilterFunc defines the signature of the callback used to
// convert from T to PbT and filter the results.
type ConvertAndFilterFunc[T any, PbT ResponseItem] func(item T) (PbT, error)

// PaginateRequest performs refresh token parsing and validation
// and performs pagination as specified by the request page size
// and service configured max page size using the itemLister. It
// will call the itemLister until it has filled a page, or until
// there are no more results available.
func PaginateRequest[T any, PbT ResponseItem](
	ctx context.Context,
	maxPageSize uint,
	resourceType pbs.ResourceType,
	req ListRequest,
	itemLister ListItemsFunc[T],
	converterAndFilterer ConvertAndFilterFunc[T, PbT],
	grantsHasher GrantsHasher,
	repo Repository,
) (*ListResponse[PbT], error) {
	const op = "pagination.PaginateRequest"

	if maxPageSize == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "max page size is required")
	}
	if resourceType == pbs.ResourceType_RESOURCE_TYPE_UNSPECIFIED {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type is required")
	}
	if util.IsNil(req) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "the request is required")
	}
	if itemLister == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "item list function is required")
	}
	if converterAndFilterer == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "convert-and-filter function is required")
	}
	if util.IsNil(grantsHasher) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "grants hasher is required")
	}
	if util.IsNil(repo) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is required")
	}

	grantsHash, err := grantsHasher.GrantsHash(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var refreshToken *pbs.ListRefreshToken
	// Note that we have to set the create time of the new refresh token before
	// we list the deleted IDs or items, or we risk missing items that were deleted between
	// listing deleted IDs or items and the creation of the refresh token. Duplicates are okay.
	newRefreshTokenCreateTime, err := repo.Now(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	resp := &ListResponse[PbT]{}
	if req.GetRefreshToken() != "" {
		// Note that refresh token parsing and validation happens after authorization,
		// since validation requires access to the grants hash.
		refreshToken, err = parseRefreshToken(ctx, req.GetRefreshToken())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if err := validateRefreshToken(ctx, refreshToken, grantsHash, resourceType); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		// List deleted IDs before listing the items to avoid including deleted
		// items in the results (any item that is deleted between listing items
		// and listing deleted IDs would show up in both).
		// We also assign the new refresh token create time such that it can safely
		// be used to get deleted IDs next time without risking bugs from clock skew
		// between the controller and DB.
		resp.DeletedIds, err = repo.ListDeletedIds(ctx, refreshToken.GetCreatedTime().AsTime())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	pageSize := int(maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < maxPageSize {
		pageSize = int(req.GetPageSize())
	}
	// request page size+1 so we can tell if we're at the end
	limit := pageSize + 1

	resp.Items, resp.CompleteListing, err = fillPage(ctx, limit, pageSize, refreshToken, itemLister, converterAndFilterer)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// Only include a refresh token if we received a result
	// or we have an incoming refresh token, so that we always have
	// something to populate LastItemId and LastItemUpdatedTime with.
	if len(resp.Items) > 0 || refreshToken != nil {
		newRefreshToken := &pbs.ListRefreshToken{
			CreatedTime:         timestamppb.New(newRefreshTokenCreateTime),
			ResourceType:        resourceType,
			PermissionsHash:     grantsHash,
			LastItemId:          refreshToken.GetLastItemId(),
			LastItemUpdatedTime: refreshToken.GetLastItemUpdatedTime(),
		}
		if len(resp.Items) > 0 {
			newRefreshToken.LastItemId = resp.Items[len(resp.Items)-1].GetId()
			newRefreshToken.LastItemUpdatedTime = resp.Items[len(resp.Items)-1].GetUpdatedTime()
		}
		resp.MarshaledRefreshToken, err = marshalRefreshToken(ctx, newRefreshToken)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	if refreshToken == nil && resp.CompleteListing {
		// This single page contains all visible items, set
		// estimated item count based on length of the items
		// slice directly
		resp.EstimatedItemCount = len(resp.Items)
	} else {
		resp.EstimatedItemCount, err = repo.EstimatedCount(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	return resp, nil
}

// fillPage repeatedly calls listItemsFn until it has gathered pageSize number of items,
// subject to the convertAndFilterFunc, or until there are no more results.
// It reports whether it reached the end of iteration.
func fillPage[T any, PbT ResponseItem](
	ctx context.Context,
	limit int,
	pageSize int,
	refreshToken *pbs.ListRefreshToken,
	listItemsFn ListItemsFunc[T],
	convertAndFilterFn ConvertAndFilterFunc[T, PbT],
) ([]PbT, bool, error) {
	const op = "pagination.fillPage"

	// Ensure we can fill pageSize+1 items
	// so we know if we're at the end
	finalItems := make([]PbT, 0, pageSize+1)
	// Loop until we've filled the page
	var lastItem T
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		page, err := listItemsFn(lastItem, refreshToken, limit)
		if err != nil {
			return nil, false, errors.Wrap(ctx, err, op)
		}
		for _, item := range page {
			pbItem, err := convertAndFilterFn(item)
			if err != nil {
				return nil, false, errors.Wrap(ctx, err, op)
			}
			var zero PbT
			if pbItem != zero {
				finalItems = append(finalItems, pbItem)
				// If we filled the items after filtering,
				// we're done.
				if len(finalItems) == cap(finalItems) {
					break dbLoop
				}
			}
		}
		// If the current page was shorter than the limit, stop iterating
		if len(page) < limit {
			break dbLoop
		}

		lastItem = page[len(page)-1]
	}
	// If we couldn't fill the items, it was a complete listing.
	completeListing := len(finalItems) < cap(finalItems)
	if !completeListing {
		// Items is of size pageSize+1, so
		// truncate if it was filled.
		finalItems = finalItems[:pageSize]
	}

	return finalItems, completeListing, nil
}

// parseRefreshToken parses a refresh token from the input, returning
// an error if the parsing fails.
func parseRefreshToken(ctx context.Context, token string) (*pbs.ListRefreshToken, error) {
	const op = "list.parseRefreshToken"
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

// marshalRefreshToken marshals a refresh token to its string representation.
func marshalRefreshToken(ctx context.Context, token *pbs.ListRefreshToken) (string, error) {
	const op = "list.marshalRefreshToken"
	if token == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "token is required")
	}
	marshaled, err := proto.Marshal(token)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return base58.Encode(marshaled), nil
}

// validateRefreshToken validates the refresh token against the inputs
// and the current time.
func validateRefreshToken(ctx context.Context, token *pbs.ListRefreshToken, grantsHash []byte, resourceType pbs.ResourceType) error {
	const op = "list.validateRefreshToken"
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
