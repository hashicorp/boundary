// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// setScopeStoragePolicyId fetches the storage policy associated with the given
// scope and sets its StoragePolicyId field if an association does exist. If no
// record is found, a RecordNotFound error is returned.
func setScopeStoragePolicyId(ctx context.Context, r db.Reader, scope *Scope) error {
	const op = "iam.setScopeStoragePolicyId"
	var policy *ScopePolicyStoragePolicy
	if err := r.SearchWhere(ctx, &policy, "scope_id = ?", []any{scope.PublicId}); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if policy.ScopePolicyStoragePolicy == nil {
		return errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("%s scope storage policy not found", scope.PublicId), errors.WithoutEvent())
	}
	scope.StoragePolicyId = policy.GetStoragePolicyId()
	return nil
}
