// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package warehouse

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

type Repository struct {
	reader db.Reader
}

func NewRepository(ctx context.Context, r db.Reader) (*Repository, error) {
	const op = "warehouse.NewRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil db reader")
	}

	return &Repository{
		reader: r,
	}, nil
}

func (r *Repository) RunSQLQuery(ctx context.Context, query string) ([]any, error) {
	const op = "warehouse.Repository.RunSQLQuery"

	if query == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty query")
	}

	rows, err := r.reader.Query(ctx, query, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to get columns"))
	}

	results := make([]any, 0)
	for rows.Next() {
		columnValues := make([]any, len(columns))
		columnPointers := make([]any, len(columns))

		for i := range columnValues {
			columnPointers[i] = &columnValues[i]
		}

		if err := rows.Scan(columnPointers...); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		rowMap := make(map[string]any)
		for i, colName := range columns {
			rowMap[colName] = columnValues[i]
		}
		results = append(results, rowMap)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error iterating over rows"))
	}
	return results, nil
}
