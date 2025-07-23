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

// Table "public.wh_credential_group"
// Column |    Type    | Collation | Nullable |   Default
// --------+------------+-----------+----------+--------------
// key    | wh_dim_key |           | not null | wh_dim_key()
// Indexes:
//    "wh_credential_group_pkey" PRIMARY KEY, btree (key)
// Referenced by:
//    TABLE "wh_session_accumulating_fact" CONSTRAINT "wh_credential_group_credential_group_key_fkey" FOREIGN KEY (credential_group_key) REFERENCES wh_credential_group(key) ON UPDATE CASCADE ON DELETE RESTRICT
//    TABLE "wh_session_connection_accumulating_fact" CONSTRAINT "wh_credential_group_credential_group_key_fkey" FOREIGN KEY (credential_group_key) REFERENCES wh_credential_group(key) ON UPDATE CASCADE ON DELETE RESTRICT
//    TABLE "wh_credential_group_membership" CONSTRAINT "wh_credential_group_membership_credential_group_key_fkey" FOREIGN KEY (credential_group_key) REFERENCES wh_credential_group(key) ON UPDATE CASCADE ON DELETE RESTRICT

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

func (r *Repository) GetWarehouseSchemas(ctx context.Context) ([]string, error) {
	const op = "warehouse.Repository.GetWarehouseSchemas"

	query := getWarehouseSchemasQuery // TODO: Dump schema to file & read from that instead of the database
	rows, err := r.reader.Query(ctx, query, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var schemas []string
	for rows.Next() {
		var schema string
		if err := rows.Scan(&schema); err != nil {
			return nil, err
		}
		schemas = append(schemas, schema)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return schemas, nil
}
