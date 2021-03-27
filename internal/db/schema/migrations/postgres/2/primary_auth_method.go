package migration

import (
	"context"
	"database/sql"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	missingPrimaryAuthMethodMsg = "scope %s has more than one existing auth method, so we didn't set a primary auth method"
)

func PrimaryAuthMethod(ctx context.Context, tx *sql.Tx, logWriter io.Writer) error {
	const op = "migrations.PrimaryAuthMethod"
	if tx == nil {
		return errors.New(errors.InvalidParameter, op, "missing tx")
	}
	if logWriter == nil {
		return errors.New(errors.InvalidParameter, op, "missing log writer")
	}
	if _, err := setPrimaryAuthMethods(ctx, tx); err != nil {
		return errors.Wrap(err, op)
	}

	scopesWithoutPrimaryAuthMethod, err := findScopesWithNoPrimary(ctx, tx)
	if err != nil {
		return errors.Wrap(err, op)
	}
	for _, s := range scopesWithoutPrimaryAuthMethod {
		l, err := logWriter.Write([]byte(fmt.Sprintf(missingPrimaryAuthMethodMsg, s)))
		if err != nil {
			return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to write scope %s has no primary auth method msg", s)))
		}
		if l == 0 {
			return errors.New(errors.Internal, op, "")
		}
	}
	return nil
}

func setPrimaryAuthMethods(ctx context.Context, tx *sql.Tx) (int, error) {
	const op = "migration.setPrimaryAuthMethods"
	if tx == nil {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing tx")
	}
	const sql = `
with single_authmethod (scope_id, public_id) as (
select 
	am.scope_id, 
	am.public_id  
from 
	auth_password_method am,
	(select scope_id, count(public_id) as cnt from auth_password_method group by scope_id) as singles
where 
	am.public_id = singles.scope_id and 
	singles.cnt = 1
)
update 
    iam_scope
set 
    primary_auth_method_id = p.public_id
from
    single_authmethod as p
where p.scope_id = iam_scope.public_id;
`
	res, err := tx.ExecContext(ctx, sql)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to set primary auth methods for scopes"))
	}
	rowsUpdated, err := res.RowsAffected()
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to determine the number of scopes updated with a primary auth method"))
	}
	return int(rowsUpdated), nil
}

func findScopesWithNoPrimary(ctx context.Context, tx *sql.Tx) (scopeIds []string, e error) {
	const op = "migration.findScopesWithNoPrimary"
	if tx == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing tx")
	}
	const sql = `
 select 
	am.scope_id, 
	am.public_id  
from 
	auth_password_method am,
	(select scope_id, count(public_id) as cnt from auth_password_method group by scope_id) as singles
where 
	am.public_id = singles.scope_id and 
	singles.cnt > 1;

`
	rows, err := tx.QueryContext(ctx, sql)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var scopeId string
		err = rows.Scan(&scopeId)
		if err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to scan scope id"))
		}
		ids = append(ids, scopeId)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("error reading rows"))
	}
	return ids, nil
}
