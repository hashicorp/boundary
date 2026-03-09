// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package alias

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

// lookupAliasByValue returns the Alias for the provided value. Returns nil, nil
// if no Alias is found for the provided value. No Options are currently supported
func (r *Repository) lookupAliasByValue(ctx context.Context, value string) (*Alias, error) {
	const op = "alias.(Repository).LookupAliasByValue"
	if value == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "value is empty")
	}
	a := allocAlias()
	if err := r.reader.LookupWhere(ctx, a, "value = $1", []any{value}); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %q", value)))
	}
	return a, nil
}
