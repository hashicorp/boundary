package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// CreateUser will create a user in the repository and return the written user
func (r *Repository) CreateUser(ctx context.Context, user *User, opt ...Option) (*User, error) {
	opts := getOpts(opt...)
	if user == nil {
		return nil, fmt.Errorf("create user: missing user %w", db.ErrInvalidParameter)
	}
	if user.PublicId != "" {
		return nil, fmt.Errorf("create user: public id is not empty %w", db.ErrInvalidParameter)
	}
	u := user.Clone().(*User)

	opts := getOpts(opt...)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, UserPrefix+"_") {
			return nil, fmt.Errorf("create user: passed-in public ID %q has wrong prefix, should be %q: %w", opts.withPublicId, UserPrefix, db.ErrInvalidPublicId)
		}
		u.PublicId = opts.withPublicId
	} else {
		id, err := newUserId()
		if err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}
		u.PublicId = id
	}
	u := user.Clone().(*User)
	u.PublicId = id

	metadata, err := r.stdMetadata(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("create user: error getting metadata for create: %w", err)
	}
	metadata["op-type"] = []string{oplog.OpType_OP_TYPE_CREATE.String()}

	scope, err := u.GetScope(ctx, r.reader)
	if err != nil {
		return nil, fmt.Errorf("create user: unable to get scope: %w", err)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("create user: unable to get oplog wrapper: %w", err)
	}

	var returnedResource interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedResource = u.Clone()
			err := w.Create(
				ctx,
				returnedResource,
				db.WithOplog(oplogWrapper, metadata),
			)
			if err != nil {
				return err
			}
			if opts.withAssociateAccountId != "" {
				if err := r.associateUserWithAccount(ctx, w, u.PublicId, opts.withAssociateAccountId, opts.associateWithDisassociate); err != nil {
					return fmt.Errorf("create: associate issue: %w", err)
				}
			}
			return nil
		},
	)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create user: user %s already exists in org %s: %w", user.Name, user.ScopeId, err)
		}
		return nil, fmt.Errorf("create user: %w for %s", err, u.PublicId)
	}
	return returnedResource.(*User), err
}

// UpdateUser will update a user in the repository and return the written user.
// fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name and Description are the only updatable fields,
// If no updatable fields are included in the fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateUser(ctx context.Context, user *User, version uint32, fieldMaskPaths []string, opt ...Option) (*User, string, int, error) {
	opts := getOpts(opt...)
	if user == nil {
		return nil, "", db.NoRowsAffected, fmt.Errorf("update user: missing user %w", db.ErrInvalidParameter)
	}
	if user.PublicId == "" {
		return nil, "", db.NoRowsAffected, fmt.Errorf("update user: missing user public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, "", db.NoRowsAffected, fmt.Errorf("update user: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"name":        user.Name,
			"description": user.Description,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 && opts.withAssociateAccountId == "" && opts.withDisassociateAccountId == "" {
		return nil, "", db.NoRowsAffected, fmt.Errorf("update user: %w", db.ErrEmptyFieldMask)
	}

	u := user.Clone().(*User)

	metadata, err := r.stdMetadata(ctx, u)
	if err != nil {
		return nil, "", db.NoRowsAffected, fmt.Errorf("error getting metadata for update: %w", err)
	}
	metadata["op-type"] = []string{oplog.OpType_OP_TYPE_UPDATE.String()}

	dbOpts := []db.Option{
		db.WithVersion(&version),
	}
	if opts.withSkipVetForWrite {
		dbOpts = append(dbOpts, db.WithSkipVetForWrite(true))
	}

	scope, err := u.GetScope(ctx, r.reader)
	if err != nil {
		return nil, "", db.NoRowsAffected, fmt.Errorf("unable to get scope: %w", err)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, "", db.NoRowsAffected, fmt.Errorf("unable to get oplog wrapper: %w", err)
	}
	dbOpts = append(dbOpts, db.WithOplog(oplogWrapper, metadata))

	var rowsUpdated int
	var returnedUser *User
	var returnedAccountId string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			if len(dbMask) != 0 || len(nullFields) != 0 {
				returnedUser = u.Clone().(*User)
				rowsUpdated, err = w.Update(
					ctx,
					returnedUser,
					dbMask,
					nullFields,
					dbOpts...,
				)
				if err == nil && rowsUpdated > 1 {
					// return err, which will result in a rollback of the update
					return errors.New("error more than 1 resource would have been updated ")
				}
			}
			switch {
			case opts.withAssociateAccountId != "":
				if err := r.associateUserWithAccount(ctx, w, u.PublicId, opts.withAssociateAccountId, opts.associateWithDisassociate); err != nil {
					return fmt.Errorf("update: associate issue: %w", err)
				}
				returnedAccountId = opts.withAssociateAccountId
			case opts.withDisassociateAccountId != "":
				if err := r.dissociateUserWithAccount(ctx, w, u.PublicId, opts.withDisassociateAccountId); err != nil {
					return fmt.Errorf("update: disassociate issue: %w", err)
				}
				returnedAccountId = "" // not needed, but clear for the reader that it's now empty
			}
			return err
		},
	)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, "", db.NoRowsAffected, fmt.Errorf("update user: user %s already exists in org %s", user.Name, user.ScopeId)
		}
		return nil, "", db.NoRowsAffected, fmt.Errorf("update user: %w for %s", err, user.PublicId)
	}
	return returnedUser, returnedAccountId, rowsUpdated, err
}

// LookupUser will look up a user in the repository.  If the user is not
// found, it will return nil, nil.
func (r *Repository) LookupUser(ctx context.Context, withPublicId string, opt ...Option) (*User, error) {
	if withPublicId == "" {
		return nil, fmt.Errorf("lookup user: missing public id %w", db.ErrInvalidParameter)
	}

	user := allocUser()
	user.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup user: failed %w for %s", err, withPublicId)
	}
	return &user, nil
}

// DeleteUser will delete a user from the repository
func (r *Repository) DeleteUser(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete user: missing public id %w", db.ErrInvalidParameter)
	}
	user := allocUser()
	user.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete user: failed %w for %s", err, withPublicId)
	}
	rowsDeleted, err := r.delete(ctx, &user)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete user: failed %w for %s", err, withPublicId)
	}
	return rowsDeleted, nil
}

// ListUsers in an org and supports the WithLimit option.
func (r *Repository) ListUsers(ctx context.Context, withOrgId string, opt ...Option) ([]*User, error) {
	if withOrgId == "" {
		return nil, fmt.Errorf("list users: missing org id %w", db.ErrInvalidParameter)
	}
	var users []*User
	err := r.list(ctx, &users, "scope_id = ?", []interface{}{withOrgId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// LookupUserWithLogin will attempt to lookup the user with a matching
// account id and return the user if found. If a user is not found and the
// WithAutoVivify() option is true, then a new iam User will be
// created in the scope of the account, and associated with the
// account. If a new user is auto vivified, then the WithName and
// WithDescription options are supported as well.
func (r *Repository) LookupUserWithLogin(ctx context.Context, accountId string, opt ...Option) (*User, error) {
	opts := getOpts(opt...)
	if accountId == "" {
		return nil, fmt.Errorf("lookup user with login: missing account id %w", db.ErrInvalidParameter)
	}
	u, err := r.LookupUserWithAccount(ctx, accountId)
	if err != nil {
		return nil, fmt.Errorf("lookup user with login: %w", err)
	}
	if u != nil {
		return u, nil
	}
	if !opts.withAutoVivify {
		return nil, fmt.Errorf("lookup user with login: user not found for account %s: %w", accountId, db.ErrRecordNotFound)
	}

	acct := allocAccount()
	acct.PublicId = accountId
	err = r.reader.LookupByPublicId(context.Background(), &acct)
	if err != nil {
		return nil, fmt.Errorf("lookup user with login: unable to lookup account %s: %w", accountId, err)
	}

	metadata := oplog.Metadata{
		"resource-public-id": []string{accountId},
		"scope-id":           []string{acct.ScopeId},
		"scope-type":         []string{scope.Org.String()},
		"resource-type":      []string{"auth-account"},
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, acct.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("lookup user with login: unable to get oplog wrapper: %w", err)
	}

	// We will create a new user and associate the user with the account
	// within one retryable transaction using writer.DoTx
	var obtainedUser *User
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			ticket, err := w.GetTicket(&acct)
			if err != nil {
				return err
			}
			obtainedUser, err = NewUser(acct.ScopeId, opt...)
			if err != nil {
				return err
			}
			id, err := newUserId()
			if err != nil {
				return err
			}
			var createMsg oplog.Message
			obtainedUser.PublicId = id
			err = w.Create(ctx, obtainedUser, db.NewOplogMsg(&createMsg))
			if err != nil {
				return err
			}
			msgs = append(msgs, &createMsg)

			var updateMsg oplog.Message
			updateAcct := acct.Clone().(*authAccount)
			updateAcct.IamUserId = id
			updatedRows, err := w.Update(ctx, updateAcct, []string{"IamUserId"}, nil, db.NewOplogMsg(&updateMsg))
			if err != nil {
				return err
			}
			if updatedRows != 1 {
				return fmt.Errorf("account update affected %d rows", updatedRows)
			}
			msgs = append(msgs, &updateMsg)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("lookup user with login: unable to associate user and account: %w", err)
	}
	return obtainedUser, nil
}

// LookupUserWithAccount will lookup the user in the repo that's associated with
// the account id.  No options are currently supported.
func (r *Repository) LookupUserWithAccount(ctx context.Context, withAccountId string, opt ...Option) (*User, error) {
	if withAccountId == "" {
		return nil, fmt.Errorf("missing account id %w", db.ErrInvalidParameter)
	}
	underlying, err := r.reader.DB()
	if err != nil {
		return nil, fmt.Errorf("unable to get underlying db for account search: %w", err)
	}
	rows, err := underlying.Query(whereUserAccount, withAccountId)
	if err != nil {
		return nil, fmt.Errorf("unable to query account %s", withAccountId)
	}
	defer rows.Close()
	u := allocUser()
	if rows.Next() {
		err = r.reader.ScanRows(rows, &u)
		if err != nil {
			return nil, fmt.Errorf("unable to scan rows for account %s: %w", withAccountId, err)
		}
	} else {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("unable to get next account: %w", err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unable to get next row for accounts %s: %w", withAccountId, err)
	}
	return &u, nil
}

// associateUserWithAccount will associate a user with an existing account.
// The account must not already be associated with a different user.
// opts.withDisassociate is supported.
func (r *Repository) associateUserWithAccount(ctx context.Context, w db.Writer, userPublicId, accountId string, withDisassociate bool) error {
	if userPublicId == "" {
		return fmt.Errorf("associate user with account: missing user %w", db.ErrInvalidParameter)
	}
	if accountId == "" {
		return fmt.Errorf("associate user with account: missing account id %w", db.ErrInvalidParameter)
	}

	acct := allocAccount()
	acct.PublicId = accountId
	err := r.reader.LookupByPublicId(context.Background(), &acct)
	if err != nil {
		return fmt.Errorf("associate user with account: unable to lookup account %s: %w", accountId, err)
	}
	// first, let's handle the case where the account is already
	// associated with the user, so we're done!
	if acct.IamUserId == userPublicId {
		return nil
	}

	if !withDisassociate {
		if acct.IamUserId != "" && acct.IamUserId != userPublicId {
			return fmt.Errorf("associate user with account: %s account is already associated with a user: %w", accountId, db.ErrInvalidParameter)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, acct.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return fmt.Errorf("associate user with account: unable to get oplog wrapper: %w", err)
	}

	metadata := oplog.Metadata{
		"resource-public-id": []string{accountId},
		"scope-id":           []string{acct.ScopeId},
		"scope-type":         []string{scope.Org.String()},
		"resource-type":      []string{"auth-account"},
		"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
	}
	var updatedRows int
	updatedAcct := acct.Clone().(*authAccount)
	updatedAcct.IamUserId = userPublicId
	// we are using WithWhere to make sure the account is not
	// associated with a user (handling race conditions with concurrent
	// transactions)
	switch {
	case withDisassociate:
		updatedRows, err = w.Update(ctx, updatedAcct, []string{"IamUserId"}, nil, db.WithOplog(oplogWrapper, metadata), db.WithWhere("iam_user_id = ?", acct.IamUserId))
	default:
		updatedRows, err = w.Update(ctx, updatedAcct, []string{"IamUserId"}, nil, db.WithOplog(oplogWrapper, metadata), db.WithWhere("iam_user_id is NULL"))
	}
	if err != nil {
		return fmt.Errorf("associate user with account: %w", err)
	}
	if updatedRows != 1 {
		return fmt.Errorf("account update affected %d rows", updatedRows)
	}
	return nil
}

// dissociateUserWithAccount will dissociate a user with its existing account.
// An error is returned if account is associated with a different user.
func (r *Repository) dissociateUserWithAccount(ctx context.Context, w db.Writer, userPublicId, accountId string) error {
	if userPublicId == "" {
		return fmt.Errorf("dissociate user with account: missing user public id %w", db.ErrInvalidParameter)
	}
	if accountId == "" {
		return fmt.Errorf("dissociate user with account: missing account id %w", db.ErrInvalidParameter)
	}

	acct := allocAccount()
	acct.PublicId = accountId
	err := r.reader.LookupByPublicId(ctx, &acct)
	if err != nil {
		return fmt.Errorf("dissociate user with account: unable to lookup account %s: %w", accountId, err)
	}
	// first, let's handle the case where the account is not associated
	// with any user, so we're done!
	if acct.IamUserId == "" {
		return nil
	}
	// before proceeding with an update, is the account associated with the different user?
	if acct.IamUserId != userPublicId {
		return fmt.Errorf("dissociate user with account: %s account is not associated with user %s: %w", accountId, userPublicId, db.ErrInvalidParameter)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, acct.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return fmt.Errorf("disassociate user with account: unable to get oplog wrapper: %w", err)
	}

	// validate, dissociate the user with the account and then read the user back in
	// the same tx for consistency.

	metadata := oplog.Metadata{
		"resource-public-id": []string{accountId},
		"scope-id":           []string{acct.ScopeId},
		"scope-type":         []string{scope.Org.String()},
		"resource-type":      []string{"auth-account"},
		"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
	}
	updatedAcct := acct.Clone().(*authAccount)
	updatedAcct.IamUserId = ""
	// set the user id to null and use WithWhere to ensure that the auth
	// account is associated with the user (handling race conditions
	// with other concurrent transactions)
	updatedRows, err := w.Update(ctx, updatedAcct, nil, []string{"IamUserId"}, db.WithOplog(oplogWrapper, metadata), db.WithWhere("iam_user_id = ?", userPublicId))
	if err != nil {
		return fmt.Errorf("dissociate user with account: %w", err)
	}
	if updatedRows != 1 {
		return fmt.Errorf("account update affected %d rows", updatedRows)
	}
	return nil
}

// func lookupAccountId(ctx context.Context, reader db.Reader, userPublicId string) (string, error) {
// 	var acct authAccount

// 	reader.LookupWhere(ctx, &acct, "")

// }
