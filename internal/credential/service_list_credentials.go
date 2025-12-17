// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/util"
)

// CredentialService defines the interface expected
// to list credentials, deleted credential IDs and get
// an estimate count of total credentials.
type CredentialService interface {
	EstimatedCredentialCount(context.Context) (int, error)
	ListDeletedCredentialIds(context.Context, time.Time) ([]string, time.Time, error)
	ListCredentials(context.Context, string, ...Option) ([]Static, time.Time, error)
	ListCredentialsRefresh(context.Context, string, time.Time, ...Option) ([]Static, time.Time, error)
}

// List lists up to page size credentials, filtering out entries that
// do not pass the filter item function. It will automatically request
// more credentials from the database, at page size chunks, to fill the page.
// It returns a new list token used to continue pagination or refresh items.
// Credentials are ordered by create time descending (most recently created first).
func List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Static],
	service CredentialService,
	credentialStoreId string,
) (*pagination.ListResponse[Static], error) {
	const op = "credential.List"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case util.IsNil(service):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing service")
	case credentialStoreId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential store ID")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Static, limit int) ([]Static, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		return service.ListCredentials(ctx, credentialStoreId, opts...)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, service.EstimatedCredentialCount)
}
