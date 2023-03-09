// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
)

// CreateAccount inserts an Account, a, into the repository and returns a
// new Account containing its PublicId. a is not changed. a must contain a
// valid AuthMethodId. a must not contain a PublicId. The PublicId is
// generated and assigned by this method. a must not contain an Issuer.
// The Issuer is retrieved from the auth method. If it does not contain an
// Issuer an error is returned.
//
// a must contain a valid Subject. a.Subject must be unique for an
// a.AuthMethod/Issuer pair.
//
// Both a.Name and a.Description are optional. If a.Name is set, it must be
// unique within a.AuthMethodId.
//
// WithPublicId is currently the only valid option.
func (r *Repository) CreateAccount(ctx context.Context, scopeId string, a *Account, opt ...Option) (*Account, error) {
	const op = "oidc.(Repository).CreateAccount"
	if a == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing Account")
	}
	if a.Account == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing embedded Account")
	}
	if a.AuthMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	if a.Subject == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing subject")
	}
	if a.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id must be empty")
	}
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	a = a.Clone()

	// If the account doesn't provide an issuer, default to the one provided by
	// the auth method. While this potentially creates a race condition between
	// modifying the auth method's issuer and setting the it on the account
	// the value set on the account is reported back to the requester by the api
	// and setting an issuer on an account that doesn't match the auth method is
	// perfectly valid and allows an operator to provision accounts prior to
	// configuring the auth method to specify issuer.
	if a.Issuer == "" {
		am, err := r.LookupAuthMethod(ctx, a.AuthMethodId)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get auth method"))
		}
		if am.GetIssuer() == "" {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "no issuer on auth method")
		}
		a.Issuer = am.GetIssuer()
	}
	if a.Issuer == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no issuer provided or defined in auth method")
	}

	opts := getOpts(opt...)
	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, globals.OidcAccountPrefix+"_") {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "chosen account id does not have a valid prefix")
		}
		a.PublicId = opts.withPublicId
	} else {
		id, err := newAccountId(ctx, a.AuthMethodId, a.Issuer, a.Subject)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		a.PublicId = id
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"), errors.WithCode(errors.Encrypt))
	}

	var newAccount *Account
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newAccount = a.Clone()
			if err := w.Create(ctx, newAccount, db.WithOplog(oplogWrapper, a.oplog(oplog.OpType_OP_TYPE_CREATE, scopeId))); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf(
				"in auth method %s: name %q already exists or subject %q already exists for issuer %q in scope %s",
				a.AuthMethodId, a.Name, a.Subject, a.Issuer, scopeId))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(a.AuthMethodId))
	}
	return newAccount, nil
}

// LookupAccount will look up an account in the repository.  If the account is not
// found, it will return nil, nil.  All options are ignored.
func (r *Repository) LookupAccount(ctx context.Context, withPublicId string, opt ...Option) (*Account, error) {
	const op = "oidc.(Repository).LookupAccount"
	if withPublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	a := AllocAccount()
	a.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, a); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", withPublicId)))
	}
	return a, nil
}

// ListAccounts in an auth method and supports WithLimit option.
func (r *Repository) ListAccounts(ctx context.Context, withAuthMethodId string, opt ...Option) ([]*Account, error) {
	const op = "oidc.(Repository).ListAccounts"
	if withAuthMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var accts []*Account
	err := r.reader.SearchWhere(ctx, &accts, "auth_method_id = ?", []any{withAuthMethodId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return accts, nil
}

// DeleteAccount deletes the account for the provided id from the repository returning a count of the
// number of records deleted.  All options are ignored.
func (r *Repository) DeleteAccount(ctx context.Context, scopeId, withPublicId string, opt ...Option) (int, error) {
	const op = "oidc.(Repository).DeleteAccount"
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if scopeId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	ac := AllocAccount()
	ac.PublicId = withPublicId

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			metadata := ac.oplog(oplog.OpType_OP_TYPE_DELETE, scopeId)
			dAc := ac.Clone()
			rowsDeleted, err = w.Delete(ctx, dAc, db.WithOplog(oplogWrapper, metadata))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)

	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(withPublicId))
	}

	return rowsDeleted, nil
}

// UpdateAccount updates the repository entry for a.PublicId with the
// values in a for the fields listed in fieldMaskPaths. It returns a new
// Account containing the updated values and a count of the number of
// records updated. a is not changed.
//
// a must contain a valid PublicId. Only a.Name and a.Description can be
// updated. If a.Name is set to a non-empty string, it must be unique within
// a.AuthMethodId.
//
// An attribute of a will be set to NULL in the database if the attribute
// in a is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateAccount(ctx context.Context, scopeId string, a *Account, version uint32, fieldMaskPaths []string, opt ...Option) (*Account, int, error) {
	const op = "oidc.(Repository).UpdateAccount"
	if a == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing Account")
	}
	if a.Account == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded Account")
	}
	if a.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if scopeId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(NameField, f):
		case strings.EqualFold(DescriptionField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			NameField:        a.Name,
			DescriptionField: a.Description,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt),
			errors.WithMsg(("unable to get oplog wrapper")))
	}

	a = a.Clone()

	metadata := a.oplog(oplog.OpType_OP_TYPE_UPDATE, scopeId)

	var rowsUpdated int
	var returnedAccount *Account
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedAccount = a.Clone()
			var err error
			rowsUpdated, err = w.Update(ctx, returnedAccount, dbMask, nullFields, db.WithOplog(oplogWrapper, metadata), db.WithVersion(&version))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op,
				fmt.Sprintf("name %s already exists: %s", a.Name, a.PublicId))
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(a.PublicId))
	}

	return returnedAccount, rowsUpdated, nil
}
