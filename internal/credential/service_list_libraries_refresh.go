// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRefresh lists credential libraries according to the page size and refresh token,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned libraries.
func (s *LibraryService) ListRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Library],
	tok *refreshtoken.Token,
	credentialStoreId string,
) (*pagination.ListResponse2[Library], error) {
	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem Library, limit int) ([]Library, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
			)
		} else {
			opts = append(opts,
				WithStartPageAfterItem(tok.ToPartialResource()),
			)
		}
		genericLibs, err := s.repo.ListCredentialLibraries(ctx, credentialStoreId, opts...)
		if err != nil {
			return nil, err
		}
		sshCertLibs, err := s.repo.ListSSHCertificateCredentialLibraries(ctx, credentialStoreId, opts...)
		if err != nil {
			return nil, err
		}
		libs := append(genericLibs, sshCertLibs...)
		slices.SortFunc(libs, func(i, j Library) int {
			return i.GetUpdateTime().AsTime().Compare(j.GetUpdateTime().AsTime())
		})
		// Truncate slice to at most limit number of elements
		if len(libs) > limit {
			libs = libs[:limit]
		}
		return libs, nil
	}
	estimatedCountFn := func(ctx context.Context) (int, error) {
		numGenericLibs, err := s.repo.EstimatedLibraryCount(ctx)
		if err != nil {
			return 0, err
		}
		numSSHCertLibs, err := s.repo.EstimatedSSHCertificateLibraryCount(ctx)
		if err != nil {
			return 0, err
		}
		return numGenericLibs + numSSHCertLibs, nil
	}
	listDeletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
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
				return err
			}
			deletedSSHCertIds, err := s.repo.ListDeletedSSHCertificateLibraryIds(ctx, tok.UpdatedTime, WithReaderWriter(r, w))
			if err != nil {
				return err
			}
			transactionTimestamp, err = r.Now(ctx)
			if err != nil {
				return err
			}
			deletedIds = append(deletedGenericIds, deletedSSHCertIds...)
			return nil
		}); err != nil {
			return nil, time.Time{}, err
		}
		return deletedIds, transactionTimestamp, nil
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedCountFn, listDeletedIDsFn, tok)
}
