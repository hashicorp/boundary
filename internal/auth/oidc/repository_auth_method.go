package oidc

import (
	"context"
	"fmt"
	"strings"

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
	var iss, sub string
	var ok bool
	if iss, ok = IdTokenClaims["iss"].(string); !ok {
		return nil, errors.New(errors.Unknown, op, "issuer is not present in return, which should not be possible")
	}
	if sub, ok = IdTokenClaims["sub"].(string); !ok {
		return nil, errors.New(errors.Unknown, op, "subject is not present in return, which should not be possible")
	}

	columns := []string{"public_id", "auth_method_id", "issuer_id", "subject_id"}
	values := []interface{}{pubId, authMethodId, iss, sub}
	conflictClauses := []string{}

	var foundEmail, foundName interface{}
	switch {
	case AccessTokenClaims["name"] != nil:
		foundName = AccessTokenClaims["name"]
		columns, values = append(columns, "full_name"), append(values, foundName)
	case IdTokenClaims["name"] != nil:
		foundName = IdTokenClaims["name"]
		columns, values = append(columns, "full_name"), append(values, foundName)
	default:
		conflictClauses = append(conflictClauses, "full_name = NULL")
	}
	switch {
	case AccessTokenClaims["email"] != nil:
		foundEmail = AccessTokenClaims["email"]
		columns, values = append(columns, "email"), append(values, foundEmail)
	case IdTokenClaims["email"] != nil:
		foundEmail = IdTokenClaims["email"]
		columns, values = append(columns, "email"), append(values, foundEmail)
	default:
		conflictClauses = append(conflictClauses, "email = NULL")
	}

	if foundName != nil {
		values = append(values, foundName)
		conflictClauses = append(conflictClauses, fmt.Sprintf("full_name = $%d", len(values)))
	}
	if foundEmail != nil {
		values = append(values, foundEmail)
		conflictClauses = append(conflictClauses, fmt.Sprintf("email = $%d", len(values)))
	}

	placeHolders := make([]string, 0, len(columns))
	for colNum := range columns {
		placeHolders = append(placeHolders, fmt.Sprintf("$%d", colNum+1))
	}

	query := fmt.Sprintf(acctUpsertQuery, strings.Join(columns, ", "), strings.Join(placeHolders, ", "), strings.Join(conflictClauses, ", "))

	var rowsUpdated int
	updatedAcct := AllocAccount()
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			rowsUpdated, err = w.Exec(ctx, query, values)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to insert/update auth oidc account"))
			}
			if rowsUpdated > 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("expected 1 row to be updated but got: %d", rowsUpdated))
			}
			if err := reader.LookupWhere(ctx, &updatedAcct, "auth_method_id = ? and issuer_id = ? and subject_id = ?", authMethodId, iss, sub); err != nil {
				return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to look up auth oidc account for: %s / %s / %s", authMethodId, iss, sub)))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return &updatedAcct, nil
}
