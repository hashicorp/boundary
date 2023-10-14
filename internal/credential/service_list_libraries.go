// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"slices"

	"github.com/hashicorp/boundary/internal/pagination"
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
	filterItemFn pagination.ListFilterFunc[Library],
	credentialStoreId string,
) (*pagination.ListResponse2[Library], error) {
	listItemsFn := func(ctx context.Context, lastPageItem Library, limit int) ([]Library, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
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

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedCountFn)
}
