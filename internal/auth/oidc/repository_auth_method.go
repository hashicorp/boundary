package oidc

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// upsertAccount will create/update account using claims from the user's ID and Access Tokens.
func (r *Repository) upsertAccount(ctx context.Context, authMethodId string, IdTokenClaims, AccessTokenClaims map[string]interface{}) (*Account, error) {
	const op = "oidc.(Repository).upsertAccount"
	if authMethodId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	if IdTokenClaims == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing ID Token claims")
	}
	if AccessTokenClaims == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing Access Token Ccaims")
	}
	pubId, err := newAccountId()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	var iss, sub, full_name, email string
	var ok bool
	if iss, ok = IdTokenClaims["iss"].(string); !ok {
		return nil, errors.New(errors.Unknown, op, "issuer is not present in return, which should not be possible")
	}
	if sub, ok = IdTokenClaims["sub"].(string); !ok {
		return nil, errors.New(errors.Unknown, op, "subject is not present in return, which should not be possible")
	}
	// intentionally ignore "name" and "email" claims are not present and allowing them to be set to empty strings
	full_name, _ = AccessTokenClaims["name"].(string)
	email, _ = AccessTokenClaims["email"].(string)

	var rowsUpdated int
	updatedAcct := AllocAccount()
	updatedAcct.PublicId = pubId
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			rowsUpdated, err = w.Exec(ctx,
				acctUpsertQuery,
				[]interface{}{
					pubId,
					authMethodId,
					iss,
					sub,
					full_name,
					email,
				})
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to insert/update auth oidc account"))
			}
			if rowsUpdated > 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("expected 1 row to be updated but got: %d", rowsUpdated))
			}
			if err := reader.LookupByPublicId(ctx, &updatedAcct); err != nil {
				return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to look up auth oidc account %s", pubId)))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return &updatedAcct, nil
}
