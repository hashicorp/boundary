// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-dbw"

	"github.com/hashicorp/boundary/internal/errors"
)

// Writer provides a database writer for oplog operations
type Writer struct {
	*dbw.DB
}

// HasTable checks if tableName exists
func (w *Writer) hasTable(ctx context.Context, tableName string) (bool, error) {
	const op = "oplog.(Writer).hasTable"
	if tableName == "" {
		return false, errors.New(ctx, errors.InvalidParameter, op, "missing table name")
	}
	var count int64
	rw := dbw.New(w.DB)
	rows, err := rw.Query(context.Background(), "select count(*) from information_schema.tables where table_name = ? and table_type = ?", []any{tableName, "BASE TABLE"})
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}
	if ok := rows.Next(); ok {
		rw.ScanRows(rows, &count)
	}
	if err := rows.Err(); err != nil {
		return false, errors.Wrap(ctx, err, op)
	}
	return count > 0, nil
}

// CreateTableLike will create a newTableName like the model's table
// the new table should have all things like the existing model's table (defaults, constraints, indexes, etc)
func (w *Writer) createTableLike(ctx context.Context, existingTableName string, newTableName string) error {
	const op = "oplog.(Writer).createTableLike"
	if existingTableName == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing existing table name")
	}
	if newTableName == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing new table name")
	}

	sql := fmt.Sprintf(
		`CREATE TABLE "%s" ( LIKE %s INCLUDING ALL );`,
		newTableName,
		existingTableName,
	)
	_, err := dbw.New(w.DB).Exec(ctx, sql, nil)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// DropTableIfExists will drop the table if it exists
func (w *Writer) dropTableIfExists(ctx context.Context, tableName string) error {
	const op = "oplog.(Writer).dropTableIfExists"
	if tableName == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing table name")
	}
	sql := fmt.Sprintf("drop table if exists %s ", tableName)
	_, err := dbw.New(w.DB).Exec(ctx, sql, nil)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}
