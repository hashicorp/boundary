package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"golang.org/x/exp/maps"
)

type RewrapFn func(ctx context.Context, dataKeyId string, reader db.Reader, writer db.Writer, kms *Kms) error

var tableNameToRewrapFn = map[string]RewrapFn{}

// RegisterTableRewrapFn registers a function to be used to rewrap data in a specific table with a new key
func RegisterTableRewrapFn(tableName string, rewrapFn RewrapFn) {
	if _, ok := tableNameToRewrapFn[tableName]; ok {
		panic(fmt.Sprintf("rewrap function for table name %q already exists", tableName))
	}
	tableNameToRewrapFn[tableName] = rewrapFn
}

// ListTablesSupportingRewrap lists all the table names registered with a rewrap function
func ListTablesSupportingRewrap() []string {
	return maps.Keys(tableNameToRewrapFn)
}

func (k *Kms) ListDataKeyReferencers(ctx context.Context) ([]string, error) {
	const op = "kms.(Kms).ListDataKeyReferencers"
	// Gather the names of all tables that reference kms_data_key_version.private_id
	rows, err := k.reader.Query(
		ctx,
		`
	select distinct r.table_name
	from information_schema.constraint_column_usage       u
	inner join information_schema.referential_constraints fk
		on u.constraint_catalog = fk.unique_constraint_catalog
			and u.constraint_schema = fk.unique_constraint_schema
			and u.constraint_name = fk.unique_constraint_name
	inner join information_schema.key_column_usage        r
		on r.constraint_catalog = fk.constraint_catalog
			and r.constraint_schema = fk.constraint_schema
			and r.constraint_name = fk.constraint_name
	where
		u.column_name = 'private_id' and
		u.table_name = 'kms_data_key_version'
`,
		nil,
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to list foreign referencers"))
	}
	defer rows.Close()
	var tableNames []string
	for rows.Next() {
		var tableName string
		err := rows.Scan(&tableName)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to scan table name into string"))
		}
		tableNames = append(tableNames, tableName)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to iterate rows"))
	}
	return tableNames, nil
}
