// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRefresh lists credential libraries according to the page size and refresh token,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned libraries.
func (s *LibraryService) ListRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterLibraryFunc,
	tok *refreshtoken.Token,
	credentialStoreId string,
) (*ListLibrariesResponse, error) {
	const op = "credential.ListRefresh"

	// Request and combine deleted ids from the DB for generic and ssh cert libraries.
	// This statement here is the reason we need a struct for this. We need all the
	// deleted auth methods to be collated in a single transaction with a single
	// transaction timestamp. This requires access to a db Reader, which isn't available
	// to the handlers and can't be passed into this method. Therefore, a struct,
	// constructed in the controller, is necessary.
	var deletedIds []string
	var transactionTimestamp time.Time
	if _, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		deletedGenericIds, err := s.repo.ListDeletedLibraryIds(ctx, tok.UpdatedTime, WithReaderWriter(r, w))
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		deletedSSHCertIds, err := s.repo.ListDeletedSSHCertificateLibraryIds(ctx, tok.UpdatedTime, WithReaderWriter(r, w))
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		deletedIds = append(deletedGenericIds, deletedSSHCertIds...)
		return nil
	}); err != nil {
		return nil, err
	}

	limit := pageSize + 1
	opts := []Option{
		WithLimit(limit),
		WithStartPageAfterItem(tok.ToPartialResource()),
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
	if !completeListing {
		// Items is of size pageSize+1, so
		// truncate if it was filled.
		libraries = libraries[:pageSize]
	}

	var err error
	numGenericLibs, err := s.repo.EstimatedLibraryCount(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	numSSHCertLibs, err := s.repo.EstimatedSSHCertificateLibraryCount(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	resp := &ListLibrariesResponse{
		Items:               libraries,
		DeletedIds:          deletedIds,
		EstimatedTotalItems: numGenericLibs + numSSHCertLibs,
		CompleteListing:     completeListing,
	}

	// Use the timestamp of the deleted IDs transaction with a
	// buffer to account for overlapping transactions. It is okay
	// to return a deleted ID more than once. The buffer corresponds
	// to Postgres' default transaction timeout.
	updatedTime := transactionTimestamp.Add(-30 * time.Second)
	if updatedTime.Before(tok.CreatedTime) {
		// Ensure updated time isn't before created time due
		// to the buffer.
		updatedTime = tok.CreatedTime
	}
	if len(libraries) > 0 {
		resp.RefreshToken = tok.RefreshLastItem(libraries[len(libraries)-1], updatedTime)
	} else {
		resp.RefreshToken = tok.Refresh(updatedTime)
	}

	return resp, nil
}
