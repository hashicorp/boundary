// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// DeleteAuthMethod will delete the auth method from the repository.  It is
// idempotent so if the auth method was not found, return 0 (no rows affected)
// and nil.  No options are currently supported.
func (r *Repository) DeleteAuthMethod(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "ldap.(Repository).DeleteAuthMethod"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	am, err := r.LookupAuthMethod(ctx, publicId)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	if am == nil {
		// already deleted and this is not an error.
		return db.NoRowsAffected, nil
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			cp := am.clone()
			md, err := cp.oplog(ctx, oplog.OpType_OP_TYPE_DELETE)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate oplog metadata"))
			}
			rowsDeleted, err = w.Delete(ctx, cp, db.WithOplog(oplogWrapper, md))
			if err != nil {
				return err
			}
			if rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 auth method would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to delete %s", publicId)))
	}
	return rowsDeleted, nil
}
