// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

func fetchAddress(ctx context.Context, r db.Reader, targetId string) (*Address, error) {
	const op = "target.fetchAddress"
	var address *Address
	if err := r.SearchWhere(ctx, &address, "target_id = ?", []any{targetId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if address.TargetAddress == nil {
		return nil, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("%s target address not found", targetId), errors.WithoutEvent())
	}
	return address, nil
}
