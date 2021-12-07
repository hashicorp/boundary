package oplog

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-dbw"

	"github.com/hashicorp/boundary/internal/errors"
)

// GormWriter uses a gorm DB connection for writing
type OplogWriter struct {
	*dbw.DB
}

// HasTable checks if tableName exists
func (w *OplogWriter) hasTable(ctx context.Context, tableName string) (bool, error) {
	const op = "oplog.(OplogWriter).hasTable"
	if tableName == "" {
		return false, errors.New(ctx, errors.InvalidParameter, op, "missing table name")
	}
	var count int64
	rw := dbw.New(w.DB)
	rows, err := rw.Query(context.Background(), "select count(*) from information_schema.tables where table_name = ? and table_type = ?", []interface{}{tableName, "BASE TABLE"})
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}
	if ok := rows.Next(); ok {
		rw.ScanRows(rows, &count)
	}
	return count > 0, nil
}

// CreateTableLike will create a newTableName like the model's table
// the new table should have all things like the existing model's table (defaults, constraints, indexes, etc)
func (w *OplogWriter) createTableLike(ctx context.Context, existingTableName string, newTableName string) error {
	const op = "oplog.(OplogWriter).createTableLike"
	if existingTableName == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing existing table name")
	}
	if newTableName == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing new table name")
	}

	sql := fmt.Sprintf(
		`CREATE TABLE "%s" ( LIKE %s INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING INDEXES );`,
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
func (w *OplogWriter) dropTableIfExists(ctx context.Context, tableName string) error {
	const op = "oplog.(OplogWriter).dropTableIfExists"
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
