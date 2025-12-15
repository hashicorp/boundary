// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"

	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

func fetchTargetAliases(ctx context.Context, r db.Reader, targetId string) ([]*target.Alias, error) {
	const op = "target.fetchTargetAliases"
	var targetAliases []*target.Alias
	if err := r.SearchWhere(ctx, &targetAliases, "destination_id = ?", []any{targetId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return targetAliases, nil
}
