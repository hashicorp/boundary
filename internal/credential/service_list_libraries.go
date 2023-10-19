// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"slices"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// This function is a callback passed down from the application service layer
// used to filter out protobuf libraries that don't match any user-supplied filter.
type ListFilterLibraryFunc func(Library) (bool, error)

// List lists credential libraries according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned libraries.
func (s *LibraryService) List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterLibraryFunc,
	credentialStoreId string,
) (*ListLibrariesResponse, error) {
	const op = "credential.List"

	limit := pageSize + 1
	opts := []Option{
		WithLimit(limit),
	}

	libraries := make([]Library, 0, limit)
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		genericPage, err := s.repo.ListCredentialLibraries(ctx, credentialStoreId, opts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		sshCertPage, err := s.repo.ListSSHCertificateCredentialLibraries(ctx, credentialStoreId, opts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		page := append(genericPage, sshCertPage...)
		slices.SortFunc(page, func(i, j Library) int {
			return i.GetUpdateTime().AsTime().Compare(j.GetUpdateTime().AsTime())
		})
		// Truncate slice to at most limit number of elements
		if len(page) > limit {
			page = page[:limit]
		}
		for _, item := range page {
			ok, err := filterItemFn(item)
			if err != nil {
				return nil, err
			}
			if ok {
				libraries = append(libraries, item)
				// If we filled the items after filtering,
				// we're done.
				if len(libraries) == cap(libraries) {
					break dbLoop
				}
			}
		}
		// If the current page was shorter than the limit, stop iterating
		if len(page) < limit {
			break dbLoop
		}

		opts = []Option{
			WithLimit(limit),
			WithStartPageAfterItem(page[len(page)-1]),
		}
	}
	// If we couldn't fill the items, it was a complete listing.
	completeListing := len(libraries) < cap(libraries)
	totalItems := len(libraries)
	if !completeListing {
		// Items is of size pageSize+1, so
		// truncate if it was filled.
		libraries = libraries[:pageSize]
		// If this was not a complete listing, get an estimate
		// of the total items from the DB.
		var err error
		numGenericLibs, err := s.repo.EstimatedLibraryCount(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		numSSHCertLibs, err := s.repo.EstimatedSSHCertificateLibraryCount(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		totalItems = numGenericLibs + numSSHCertLibs
	}

	resp := &ListLibrariesResponse{
		Items:               libraries,
		EstimatedTotalItems: totalItems,
		CompleteListing:     completeListing,
	}

	if len(libraries) > 0 {
		resp.RefreshToken = refreshtoken.FromResource(libraries[len(libraries)-1], grantsHash)
	}

	return resp, nil
}
