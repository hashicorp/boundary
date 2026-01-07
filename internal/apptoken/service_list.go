// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

func List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*AppToken],
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*AppToken], error) {
	const op = "apptoken.List"

	return nil, errors.New(ctx, errors.Internal, op, "not implemented")
}
