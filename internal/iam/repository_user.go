// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
)

// CreateUser will create a user in the repository and return the written user
func (r *Repository) CreateUser(ctx context.Context, user *User, opt ...Option) (*User, error) {
	const op = "iam.(Repository).CreateUser"
	if user == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user")
	}
	if user.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id is not empty")
	}
	u := user.Clone().(*User)

	opts := getOpts(opt...)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, globals.UserPrefix+"_") {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("passed-in public ID %q has wrong prefix, should be %q", opts.withPublicId, globals.UserPrefix))
		}
		u.PublicId = opts.withPublicId
	} else {
		id, err := newUserId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		u.PublicId = id
	}

	// There's no need to use r.lookupUser(...) here, because the new user cannot
	// be associated with any accounts yet.  Why would you typically want to
	// call r.lookupUser(...) here vs returning the create resource?  Well, the
	// created resource doesn't include the user's primary account info (email,
	// full name, etc), since you can't run DML against the view which does
	// provide these output only attributes.  But in this case, there's no way a
	// newly created user could have any accounts, so we don't need to use
	// r.lookupUser(...). I'm adding this comment so a future version of myself
	// doesn't come along and decide to start using r.lookupUser(...) here which
	// would just be an unnecessary database lookup.  You're welcome future me.
	resource, err := r.create(ctx, u)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("user %s already exists in org %s", user.Name, user.ScopeId))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", u.PublicId)))
	}
	return resource.(*User), nil
}

// UpdateUser will update a user in the repository and return the written user
// plus its associated account ids. fieldMaskPaths provides field_mask.proto
// paths for fields that should be updated.  Fields will be set to NULL if the
// field is a zero value and included in fieldMask. Name and Description are the
// only updatable fields, if no updatable fields are included in the
// fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateUser(ctx context.Context, user *User, version uint32, fieldMaskPaths []string, opt ...Option) (*User, []string, int, error) {
	const op = "iam.(Repository).UpdateUser"
	if user == nil {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing user")
	}
	if user.PublicId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			"name":        user.Name,
			"description": user.Description,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, db.NoRowsAffected, errors.E(ctx, errors.WithCode(errors.EmptyFieldMask), errors.WithOp(op))
	}

	u := user.Clone().(*User)
	metadata, err := r.stdMetadata(ctx, u)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	metadata["op-type"] = []string{oplog.OpType_OP_TYPE_UPDATE.String()}

	dbOpts := []db.Option{
		db.WithVersion(&version),
	}
	opts := getOpts(opt...)
	if opts.withSkipVetForWrite {
		dbOpts = append(dbOpts, db.WithSkipVetForWrite(true))
	}

	scope, err := u.GetScope(ctx, r.reader)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get scope"))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	dbOpts = append(dbOpts, db.WithOplog(oplogWrapper, metadata))

	var rowsUpdated int
	var returnedUser *User
	var currentAccountIds []string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			returnedUser = u.Clone().(*User)
			rowsUpdated, err = w.Update(
				ctx,
				returnedUser,
				dbMask,
				nullFields,
				dbOpts...,
			)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit
			}
			returnedUser, err = txRepo.lookupUser(ctx, user.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current user after update"))
			}
			currentAccountIds, err = txRepo.ListUserAccounts(ctx, user.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current account ids after update"))
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("user %s already exists in org %s", user.Name, user.ScopeId))
		}
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", user.PublicId)))
	}
	return returnedUser, currentAccountIds, rowsUpdated, nil
}

// LookupUser will look up a user and its associated account ids in the
// repository.  If the user is not found, it will return nil, nil, nil.
func (r *Repository) LookupUser(ctx context.Context, userId string, _ ...Option) (*User, []string, error) {
	const op = "iam.(Repository).LookupUser"
	if userId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	user, err := r.lookupUser(ctx, userId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	currentAccountIds, err := r.ListUserAccounts(ctx, userId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current account ids"))
	}
	return user, currentAccountIds, nil
}

// DeleteUser will delete a user from the repository
func (r *Repository) DeleteUser(ctx context.Context, withPublicId string, _ ...Option) (int, error) {
	const op = "iam.(Repository).DeleteUser"
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	user := AllocUser()
	user.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", withPublicId)))
	}
	rowsDeleted, err := r.delete(ctx, &user)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", withPublicId)))
	}
	return rowsDeleted, nil
}

// LookupUserWithLogin will attempt to lookup the user with a matching
// account id and return the user if found. If a user is not found and the
// account's scope is not the PrimaryAuthMethod, then an error is returned.
// If the account's scope is the PrimaryAuthMethod, then a new iam User will be
// created (autovivified) in the scope of the account, and associated with the
// account. If a new user is auto vivified, then the WithName and
// WithDescription options are supported as well.
func (r *Repository) LookupUserWithLogin(ctx context.Context, accountId string, opt ...Option) (*User, error) {
	const op = "iam.(Repository).LookupUserWithLogin"
	if accountId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing account id")
	}
	u, err := r.getUserWithAccount(ctx, accountId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if u != nil {
		return u, nil
	}

	acct := allocAccount()
	acct.PublicId = accountId
	err = r.reader.LookupByPublicId(context.Background(), &acct)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to lookup account %s", accountId)))
	}

	allowed, err := r.allowUserAutoVivify(ctx, &acct)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if !allowed {
		return nil, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("user not found for account %s and auth method is not primary for the scope so refusing to auto-create user", accountId))
	}

	metadata := oplog.Metadata{
		"resource-public-id": []string{accountId},
		"scope-id":           []string{acct.ScopeId},
		"scope-type":         []string{scope.Org.String()},
		"resource-type":      []string{"auth-account"},
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, acct.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// We will create a new user and associate the user with the account
	// within one retryable transaction using writer.DoTx
	var obtainedUser *User
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			ticket, err := w.GetTicket(ctx, &acct)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			obtainedUser, err = NewUser(ctx, acct.ScopeId, opt...)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			id, err := newUserId(ctx)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			var createMsg oplog.Message
			obtainedUser.PublicId = id
			err = w.Create(ctx, obtainedUser, db.NewOplogMsg(&createMsg))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			msgs = append(msgs, &createMsg)

			var updateMsg oplog.Message
			updateAcct := acct.Clone().(*authAccount)
			updateAcct.IamUserId = id
			updatedRows, err := w.Update(ctx, updateAcct, []string{"IamUserId"}, nil, db.NewOplogMsg(&updateMsg))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if updatedRows != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("account update affected %d rows", updatedRows))
			}
			msgs = append(msgs, &updateMsg)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit
			}
			obtainedUser, err = txRepo.lookupUser(ctx, obtainedUser.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve user"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return obtainedUser, nil
}

// allowUserAutoVivify determines if a user can be autovivified based on the account's scope
func (r *Repository) allowUserAutoVivify(ctx context.Context, acct *authAccount) (bool, error) {
	const op = "iam.(Repository).allowUserAutoVivify"
	if acct == nil {
		return false, errors.New(ctx, errors.InvalidParameter, op, "missing account")
	}
	acctScope := AllocScope()
	acctScope.PublicId = acct.ScopeId
	err := r.reader.LookupByPublicId(context.Background(), &acctScope)
	if err != nil {
		return false, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to lookup account's scope %s", acct.ScopeId)))
	}
	return acct.AuthMethodId == acctScope.PrimaryAuthMethodId, nil
}

func (r *Repository) getUserWithAccount(ctx context.Context, withAccountId string, _ ...Option) (*User, error) {
	const op = "iam.(Repository).getUserWithAccount"
	if withAccountId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing account id")
	}
	rows, err := r.reader.Query(ctx, whereUserAccount, []any{withAccountId})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to query account %s", withAccountId)))
	}
	defer rows.Close()
	u := AllocUser()
	if rows.Next() {
		err = r.reader.ScanRows(ctx, rows, &u)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to scan rows for account %s", withAccountId)))
		}
	} else {
		if err := rows.Err(); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next account"))
		}
		return nil, nil
	}
	return &u, nil
}

// ListUserAccounts returns the account ids for the userId and supports the
// WithLimit option. Returns nil, nil when no associated accounts are found.
func (r *Repository) ListUserAccounts(ctx context.Context, userId string, opt ...Option) ([]string, error) {
	const op = "iam.(Repository).ListUserAccounts"
	if userId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	var accounts []*authAccount
	if err := r.list(ctx, &accounts, "iam_user_id = ?", []any{userId}, opt...); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(accounts) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(accounts))
	for _, aa := range accounts {
		ids = append(ids, aa.PublicId)
	}
	return ids, nil
}

// AddUserAccounts will associate a user with existing accounts and
// return a list of all associated account ids for the user. The accounts must
// not already be associated with different users.  No options are currently
// supported.
func (r *Repository) AddUserAccounts(ctx context.Context, userId string, userVersion uint32, accountIds []string, _ ...Option) ([]string, error) {
	const op = "iam.(Repository).AddUserAccounts"
	if userId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	if userVersion == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user version")
	}
	if len(accountIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing account ids")
	}

	user, err := r.lookupUser(ctx, userId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to lookup user %s", userId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, user.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var currentAccountIds []string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			userTicket, err := w.GetTicket(ctx, user)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedUser := AllocUser()
			updatedUser.PublicId = userId
			updatedUser.Version = userVersion + 1
			var userOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedUser, []string{"Version"}, nil, db.NewOplogMsg(&userOplogMsg), db.WithVersion(&userVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get user version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated user and %d rows updated", rowsUpdated))
			}
			if err := associateUserWithAccounts(ctx, r.kms, reader, w, user.PublicId, accountIds); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{user.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-public-id": []string{user.PublicId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, userTicket, metadata, []*oplog.Message{&userOplogMsg}); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit, so we'll get all
				// the account ids without a limit
			}
			currentAccountIds, err = txRepo.ListUserAccounts(ctx, user.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current account ids after adds"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return currentAccountIds, nil
}

// DeleteUserAccounts will disassociate a user from existing accounts and
// return a list of all associated account ids for the user. The accounts must
// not be associated with different users.  No options are currently
// supported.
func (r *Repository) DeleteUserAccounts(ctx context.Context, userId string, userVersion uint32, accountIds []string, _ ...Option) ([]string, error) {
	const op = "iam.(Repository).DeleteUserAccounts"
	if userId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if userVersion == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user version")
	}
	if len(accountIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing account ids")
	}

	user, err := r.lookupUser(ctx, userId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to lookup user %s", userId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, user.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var currentAccountIds []string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			userTicket, err := w.GetTicket(ctx, user)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedUser := AllocUser()
			updatedUser.PublicId = userId
			updatedUser.Version = userVersion + 1
			var userOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedUser, []string{"Version"}, nil, db.NewOplogMsg(&userOplogMsg), db.WithVersion(&userVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update user version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated user and %d rows updated", rowsUpdated))
			}
			if err := dissociateUserFromAccounts(ctx, r.kms, reader, w, user.PublicId, accountIds); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{user.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-public-id": []string{user.PublicId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, userTicket, metadata, []*oplog.Message{&userOplogMsg}); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit, so we'll get all
				// the account ids without a limit
			}
			currentAccountIds, err = txRepo.ListUserAccounts(ctx, user.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current account ids after adds"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return currentAccountIds, nil
}

// SetUserAccounts will associate a user with existing accounts and
// return a list of all associated account ids for the user. The accounts must
// not already be associated with different users.  No options are currently
// supported.
func (r *Repository) SetUserAccounts(ctx context.Context, userId string, userVersion uint32, accountIds []string, _ ...Option) ([]string, error) {
	const op = "iam.(Repository).SetUserAccounts"
	if userId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if userVersion == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	user, err := r.lookupUser(ctx, userId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to lookup user %s", userId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, user.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	var currentAccountIds []string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			associateIds, disassociateIds, err := associationChanges(ctx, reader, userId, accountIds)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to determine changes"))
			}

			// just in case we've got nothing to do...
			if len(associateIds) == 0 && len(disassociateIds) == 0 {
				// we need a new repo, that's using the same reader/writer as this TxHandler
				txRepo := &Repository{
					reader: reader,
					writer: w,
					kms:    r.kms,
					// intentionally not setting the defaultLimit, so we'll get all
					// the account ids without a limit
				}
				currentAccountIds, err = txRepo.ListUserAccounts(ctx, userId)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current account ids after set"))
				}
				return nil
			}
			userTicket, err := w.GetTicket(ctx, user)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedUser := AllocUser()
			updatedUser.PublicId = userId
			updatedUser.Version = userVersion + 1
			var userOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedUser, []string{"Version"}, nil, db.NewOplogMsg(&userOplogMsg), db.WithVersion(&userVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update user version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated user and %d rows updated", rowsUpdated))
			}

			if len(associateIds) > 0 {
				if err := associateUserWithAccounts(ctx, r.kms, reader, w, userId, associateIds); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to associate ids"))
				}
			}

			if len(disassociateIds) > 0 {
				if err := dissociateUserFromAccounts(ctx, r.kms, reader, w, userId, disassociateIds); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to disassociate ids"))
				}
			}

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{user.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-public-id": []string{userId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, userTicket, metadata, []*oplog.Message{&userOplogMsg}); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit, so we'll get all
				// the account ids without a limit
			}
			currentAccountIds, err = txRepo.ListUserAccounts(ctx, user.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current account ids after set"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return currentAccountIds, nil
}

// associateUserWithAccounts will associate the accounts (accountIds) with
// the user (userId) within the writer's database
func associateUserWithAccounts(ctx context.Context, repoKms *kms.Kms, reader db.Reader, writer db.Writer, userId string, accountIds []string, _ ...Option) error {
	const op = "iam.associateUserWithAccounts"
	if repoKms == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}
	if reader == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if writer == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if userId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	if len(accountIds) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing account ids")
	}
	authAccounts := make([]*authAccount, 0, len(accountIds))
	for _, accountId := range accountIds {
		acct := allocAccount()
		acct.PublicId = accountId
		err := reader.LookupByPublicId(ctx, &acct)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to lookup account %s", accountId)))
		}
		if acct.IamUserId != "" && acct.IamUserId != userId {
			return errors.New(ctx, errors.AccountAlreadyAssociated, op, fmt.Sprintf("%s account is already associated with another user", accountId))
		}
		authAccounts = append(authAccounts, &acct)
	}

	for _, aa := range authAccounts {
		// wrapper could be different for each authAccount depending on it's scope
		oplogWrapper, err := repoKms.GetWrapper(ctx, aa.GetScopeId(), kms.KeyPurposeOplog)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
		}

		metadata := oplog.Metadata{
			"resource-public-id": []string{aa.PublicId},
			"scope-id":           []string{aa.ScopeId},
			"resource-type":      []string{"auth-account"},
			"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
		}
		var updatedRows int
		updatedAcct := aa.Clone().(*authAccount)
		updatedAcct.IamUserId = userId
		updatedRows, err = writer.Update(ctx, updatedAcct, []string{"IamUserId"}, nil, db.WithOplog(oplogWrapper, metadata), db.WithWhere("iam_user_id is NULL or iam_user_id = ?", userId))
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed to associate %s account", aa.PublicId)))
		}
		if updatedRows == 0 {
			return errors.New(ctx, errors.AccountAlreadyAssociated, op, fmt.Sprintf("failed to associate %s account: it is already associated with another user", aa.PublicId))
		}
		if updatedRows > 1 {
			return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("failed to associate %s account: would have updated too many accounts %d", aa.PublicId, updatedRows))
		}
	}
	return nil
}

// dissociateUserFromAccounts will dissociate a user with its existing accounts
// (accountIds). An error is returned if account is associated with a different
// user.  No options are currently supported.
func dissociateUserFromAccounts(ctx context.Context, repoKms *kms.Kms, reader db.Reader, writer db.Writer, userId string, accountIds []string, _ ...Option) error {
	const op = "iam.dissociateUserFromAccounts"
	if repoKms == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}
	if reader == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if writer == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if userId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if len(accountIds) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing account ids")
	}
	authAccounts := make([]*authAccount, 0, len(accountIds))
	for _, accountId := range accountIds {
		acct := allocAccount()
		acct.PublicId = accountId
		err := reader.LookupByPublicId(context.Background(), &acct)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to lookup account %s", accountId)))
		}
		if acct.IamUserId != userId {
			return errors.New(ctx, errors.AccountAlreadyAssociated, op, fmt.Sprintf("%s account is not associated with user %s", accountId, userId))
		}
		authAccounts = append(authAccounts, &acct)
	}

	for _, aa := range authAccounts {
		// wrapper could be different for each authAccount depending on it's scope
		oplogWrapper, err := repoKms.GetWrapper(ctx, aa.GetScopeId(), kms.KeyPurposeOplog)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
		}
		metadata := oplog.Metadata{
			"resource-public-id": []string{aa.PublicId},
			"scope-id":           []string{aa.ScopeId},
			"resource-type":      []string{"auth-account"},
			"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
		}
		var updatedRows int
		updatedAcct := aa.Clone().(*authAccount)
		updatedAcct.IamUserId = userId
		// update IamUserId to null
		updatedRows, err = writer.Update(ctx, updatedAcct, nil, []string{"IamUserId"}, db.WithOplog(oplogWrapper, metadata), db.WithWhere("iam_user_id is NULL or iam_user_id = ?", userId))
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed to disassociate %s account", aa.PublicId)))
		}
		if updatedRows == 0 {
			return errors.New(ctx, errors.AccountAlreadyAssociated, op, fmt.Sprintf("failed to disassociate %s account: it is already associated with another user", aa.PublicId))
		}
		if updatedRows > 1 {
			return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("failed to disassociate %s account: would have updated too many accounts %d", aa.PublicId, updatedRows))
		}
	}
	return nil
}

// associationChanges returns two slices: accounts to associate and disassociate
func associationChanges(ctx context.Context, reader db.Reader, userId string, accountIds []string) ([]string, []string, error) {
	const op = "iam.associationChanges"

	var inClauseSpots []string
	// starts at 2 because there is already a ? in the query
	for i := 2; i < len(accountIds)+2; i++ {
		// inClauseSpots = append(inClauseSpots, fmt.Sprintf("$%d", i))
		inClauseSpots = append(inClauseSpots, "?")
	}
	inClause := strings.Join(inClauseSpots, ",")
	if inClause == "" {
		inClause = "''"
	}
	query := fmt.Sprintf(accountChangesQuery, inClause)

	var params []any
	for _, v := range accountIds {
		params = append(params, v)
	}
	params = append(params, userId)

	rows, err := reader.Query(ctx, query, params)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	type change struct {
		Action    string
		AccountId string
	}
	var changes []*change
	for rows.Next() {
		var chg change
		if err := reader.ScanRows(ctx, rows, &chg); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		changes = append(changes, &chg)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	var associateIds, disassociateIds []string
	for _, c := range changes {
		if c.AccountId == "" {
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing account id in change result")
		}
		switch c.Action {
		case "associate":
			associateIds = append(associateIds, c.AccountId)
		case "disassociate":
			disassociateIds = append(disassociateIds, c.AccountId)
		default:
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown action %s for %s", c.Action, c.AccountId))
		}
	}
	return associateIds, disassociateIds, nil
}

// lookupUser will lookup a single user and returns nil, nil when no user is found.
// no options are currently supported
func (r *Repository) lookupUser(ctx context.Context, userId string, opt ...Option) (*User, error) {
	const op = "iam.(Repository).lookupUser"
	if userId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	ret := allocUserAccountInfo()
	ret.PublicId = userId
	if err := r.reader.LookupById(ctx, ret); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret.shallowConversion(), nil
}

// ListUsers lists users in the given scopes and supports WithLimit option.
func (r *Repository) ListUsers(ctx context.Context, withScopeIds []string, opt ...Option) ([]*User, time.Time, error) {
	const op = "iam.(Repository).listUsers"
	if len(withScopeIds) == 0 {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts := getOpts(opt...)

	limit := r.defaultLimit
	switch {
	case opts.withLimit > 0:
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	case opts.withLimit < 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "limit must be non-negative")
	}

	var args []any
	whereClause := "scope_id in @scope_ids"
	args = append(args, sql.Named("scope_ids", withScopeIds))

	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(create_time, public_id) < (@last_item_create_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}
	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("create_time desc, public_id desc")}
	return r.queryUsers(ctx, whereClause, args, dbOpts...)
}

// listUsersRefresh lists users in the given scopes and supports the
// WithLimit and WithStartPageAfterItem options.
func (r *Repository) listUsersRefresh(ctx context.Context, updatedAfter time.Time, withScopeIds []string, opt ...Option) ([]*User, time.Time, error) {
	const op = "iam.(Repository).listUsersRefresh"

	switch {
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")

	case len(withScopeIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	opts := getOpts(opt...)

	limit := r.defaultLimit
	switch {
	case opts.withLimit > 0:
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	case opts.withLimit < 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "limit must be non-negative")
	}

	var args []any
	whereClause := "update_time > @updated_after_time and scope_id in @scope_ids"
	args = append(args,
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
		sql.Named("scope_ids", withScopeIds),
	)
	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(update_time, public_id) < (@last_item_update_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("update_time desc, public_id desc")}
	return r.queryUsers(ctx, whereClause, args, dbOpts...)
}

func (r *Repository) queryUsers(ctx context.Context, whereClause string, args []any, opt ...db.Option) ([]*User, time.Time, error) {
	const op = "iam.(Repository).queryUsers"

	var transactionTimestamp time.Time
	var ret []*userAccountInfo
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(rd db.Reader, w db.Writer) error {
		var inRet []*userAccountInfo
		if err := rd.SearchWhere(ctx, &inRet, whereClause, args, opt...); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		ret = inRet
		var err error
		transactionTimestamp, err = rd.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}

	users := make([]*User, 0, len(ret))
	for _, u := range ret {
		users = append(users, u.shallowConversion())
	}

	return users, transactionTimestamp, nil
}

// listUserDeletedIds lists the public IDs of any users deleted since the timestamp provided.
func (r *Repository) listUserDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "iam.(Repository).listUserDeletedIds"
	var deletedResources []*deletedUser
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, _ db.Writer) error {
		if err := r.SearchWhere(ctx, &deletedResources, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted users"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var dIds []string
	for _, res := range deletedResources {
		dIds = append(dIds, res.PublicId)
	}
	return dIds, transactionTimestamp, nil
}

// estimatedUserCount returns an estimate of the total number of items in the iam_user table.
func (r *Repository) estimatedUserCount(ctx context.Context) (int, error) {
	const op = "iam.(Repository).estimatedUserCount"
	rows, err := r.reader.Query(ctx, estimateCountUsers, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total users"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total users"))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total users"))
	}
	return count, nil
}
