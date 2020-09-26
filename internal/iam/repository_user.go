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

	resource, err := r.create(ctx, u)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create user: user %s already exists in org %s: %w", user.Name, user.ScopeId, err)
		}
		return nil, fmt.Errorf("create user: %w for %s", err, u.PublicId)
	}
	return resource.(*User), err
}

// UpdateUser will update a user in the repository and return the written user
// plus its associated account ids. fieldMaskPaths provides field_mask.proto
// paths for fields that should be updated.  Fields will be set to NULL if the
// field is a zero value and included in fieldMask. Name and Description are the
// only updatable fields, if no updatable fields are included in the
// fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateUser(ctx context.Context, user *User, version uint32, fieldMaskPaths []string, opt ...Option) (*User, []string, int, error) {
	if user == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update user: missing user %w", db.ErrInvalidParameter)
	}
	if user.PublicId == "" {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update user: missing user public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update user: field: %s: %w", f, db.ErrInvalidFieldMask)
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
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update user: %w", db.ErrEmptyFieldMask)
	}

	u := user.Clone().(*User)
	metadata, err := r.stdMetadata(ctx, u)
	if err != nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update user: error getting metadata for update: %w", err)
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
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update user: unable to get scope: %w", err)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update user: unable to get oplog wrapper: %w", err)
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
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New("error more than 1 resource would have been updated ")
			}
			if err != nil {
				return err
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
				return fmt.Errorf("unable to retrieve current account ids after update: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update user: user %s already exists in org %s", user.Name, user.ScopeId)
		}
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update user: %w for %s", err, user.PublicId)
	}
	return returnedUser, currentAccountIds, rowsUpdated, err
}

// LookupUser will look up a user and its associated account ids in the
// repository.  If the user is not found, it will return nil, nil, nil.
func (r *Repository) LookupUser(ctx context.Context, userId string, opt ...Option) (*User, []string, error) {
	if userId == "" {
		return nil, nil, fmt.Errorf("lookup user: missing public id %w", db.ErrInvalidParameter)
	}

	user := allocUser()
	user.PublicId = userId
	if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("lookup user: failed %w for %s", err, userId)
	}
	currentAccountIds, err := r.ListUserAccounts(ctx, userId)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup user: unable to retrieve current account ids: %w", err)
	}
	return &user, currentAccountIds, nil
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
	u, err := r.getUserWithAccount(ctx, accountId)
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

func (r *Repository) getUserWithAccount(ctx context.Context, withAccountId string, opt ...Option) (*User, error) {
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

// ListUserAccounts returns the account ids for the userId and supports the
// WithLimit option. Returns nil, nil when no associated accounts are found.
func (r *Repository) ListUserAccounts(ctx context.Context, userId string, opt ...Option) ([]string, error) {
	if userId == "" {
		return nil, fmt.Errorf("list auth account ids: missing user id: %w", db.ErrInvalidParameter)
	}
	var accounts []*authAccount
	if err := r.list(ctx, &accounts, "iam_user_id = ?", []interface{}{userId}, opt...); err != nil {
		return nil, fmt.Errorf("list auth account ids: %w", err)
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
func (r *Repository) AddUserAccounts(ctx context.Context, userId string, userVersion uint32, accountIds []string, opt ...Option) ([]string, error) {
	if userId == "" {
		return nil, fmt.Errorf("associate accounts: missing user public id %w", db.ErrInvalidParameter)
	}
	if userVersion == 0 {
		return nil, fmt.Errorf("associate accounts: missing user version %w", db.ErrInvalidParameter)
	}
	if len(accountIds) == 0 {
		return nil, fmt.Errorf("associate accounts: missing account id %w", db.ErrInvalidParameter)
	}

	user := allocUser()
	user.PublicId = userId

	err := r.reader.LookupById(ctx, &user)
	if err != nil {
		return nil, fmt.Errorf("associate accounts: unable to lookup user %s: %w", userId, err)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, user.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("associate accounts: unable to get oplog wrapper: %w", err)
	}

	var currentAccountIds []string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			userTicket, err := w.GetTicket(&user)
			if err != nil {
				return fmt.Errorf("associate accounts: unable to get ticket: %w", err)
			}
			updatedUser := allocUser()
			updatedUser.PublicId = userId
			updatedUser.Version = userVersion + 1
			var userOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedUser, []string{"Version"}, nil, db.NewOplogMsg(&userOplogMsg), db.WithVersion(&userVersion))
			if err != nil {
				return fmt.Errorf("associate accounts: unable to update user version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("associate accounts: updated user and %d rows updated", rowsUpdated)
			}
			if err := associateUserWithAccounts(ctx, r.kms, reader, w, user.PublicId, accountIds); err != nil {
				return fmt.Errorf("associate accounts: %w", err)
			}
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{user.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-public-id": []string{user.PublicId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, userTicket, metadata, []*oplog.Message{&userOplogMsg}); err != nil {
				return fmt.Errorf("associate accounts: unable to write oplog: %w", err)
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
				return fmt.Errorf("associate accounts: unable to retrieve current account ids after adds: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("associate accounts: error associating account ids: %w", err)
	}
	return currentAccountIds, nil
}

// DeleteUserAccounts will disassociate a user from existing accounts and
// return a list of all associated account ids for the user. The accounts must
// not be associated with different users.  No options are currently
// supported.
func (r *Repository) DeleteUserAccounts(ctx context.Context, userId string, userVersion uint32, accountIds []string, opt ...Option) ([]string, error) {
	if userId == "" {
		return nil, fmt.Errorf("disassociate accounts: missing user public id %w", db.ErrInvalidParameter)
	}
	if userVersion == 0 {
		return nil, fmt.Errorf("disassociate accounts: missing user version %w", db.ErrInvalidParameter)
	}
	if len(accountIds) == 0 {
		return nil, fmt.Errorf("disassociate accounts: missing account id %w", db.ErrInvalidParameter)
	}

	user := allocUser()
	user.PublicId = userId
	err := r.reader.LookupById(ctx, &user)
	if err != nil {
		return nil, fmt.Errorf("disassociate accounts: unable to lookup user %s: %w", userId, err)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, user.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("disassociate accounts: unable to get oplog wrapper: %w", err)
	}

	var currentAccountIds []string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			userTicket, err := w.GetTicket(&user)
			if err != nil {
				return fmt.Errorf("disassociate accounts: unable to get ticket: %w", err)
			}
			updatedUser := allocUser()
			updatedUser.PublicId = userId
			updatedUser.Version = userVersion + 1
			var userOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedUser, []string{"Version"}, nil, db.NewOplogMsg(&userOplogMsg), db.WithVersion(&userVersion))
			if err != nil {
				return fmt.Errorf("disassociate accounts: unable to update user version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("disassociate accounts: updated user and %d rows updated", rowsUpdated)
			}
			if err := dissociateUserFromAccounts(ctx, r.kms, reader, w, user.PublicId, accountIds); err != nil {
				return fmt.Errorf("disassociate accounts: %w", err)
			}
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{user.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-public-id": []string{user.PublicId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, userTicket, metadata, []*oplog.Message{&userOplogMsg}); err != nil {
				return fmt.Errorf("disassociate accounts: unable to write oplog: %w", err)
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
				return fmt.Errorf("disassociate accounts: unable to retrieve current account ids after adds: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("disassociate accounts: error associating account ids: %w", err)
	}
	return currentAccountIds, nil
}

// SetUserAccounts will associate a user with existing accounts and
// return a list of all associated account ids for the user. The accounts must
// not already be associated with different users.  No options are currently
// supported.
func (r *Repository) SetUserAccounts(ctx context.Context, userId string, userVersion uint32, accountIds []string, opt ...Option) ([]string, error) {
	if userId == "" {
		return nil, fmt.Errorf("set associated accounts: missing user public id %w", db.ErrInvalidParameter)
	}
	if userVersion == 0 {
		return nil, fmt.Errorf("set associated accounts: missing user version %w", db.ErrInvalidParameter)
	}

	user := allocUser()
	user.PublicId = userId
	err := r.reader.LookupById(ctx, &user)
	if err != nil {
		return nil, fmt.Errorf("set associated accounts: unable to lookup user %s: %w", userId, err)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, user.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("set associated accounts: unable to get oplog wrapper: %w", err)
	}
	var currentAccountIds []string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			associateIds, disassociateIds, err := associationChanges(ctx, reader, userId, accountIds)
			if err != nil {
				return fmt.Errorf("set associated accounts: unable to determine changes: %w", err)
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
					return fmt.Errorf("set associated accounts: unable to retrieve current account ids after set: %w", err)
				}
				return nil
			}
			userTicket, err := w.GetTicket(&user)
			if err != nil {
				return fmt.Errorf("set associated accounts: unable to get ticket: %w", err)
			}
			updatedUser := allocUser()
			updatedUser.PublicId = userId
			updatedUser.Version = userVersion + 1
			var userOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedUser, []string{"Version"}, nil, db.NewOplogMsg(&userOplogMsg), db.WithVersion(&userVersion))
			if err != nil {
				return fmt.Errorf("set associated accounts: unable to update user version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("set associated accounts: updated user and %d rows updated", rowsUpdated)
			}

			if len(associateIds) > 0 {
				if err := associateUserWithAccounts(ctx, r.kms, reader, w, userId, associateIds); err != nil {
					return fmt.Errorf("set associated accounts: unable to associate ids: %w", err)
				}
			}

			if len(disassociateIds) > 0 {
				if err := dissociateUserFromAccounts(ctx, r.kms, reader, w, userId, disassociateIds); err != nil {
					return fmt.Errorf("set associated accounts: unable to disassociate ids: %w", err)
				}
			}

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{user.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-public-id": []string{userId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, userTicket, metadata, []*oplog.Message{&userOplogMsg}); err != nil {
				return fmt.Errorf("set associated accounts: unable to write oplog: %w", err)
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
				return fmt.Errorf("set associated accounts: unable to retrieve current account ids after set: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("set associated accounts: %w", err)
	}
	return currentAccountIds, nil
}

// associateUserWithAccounts will associate the accounts (accountIds) with
// the user (userId) within the writer's database
func associateUserWithAccounts(ctx context.Context, repoKms *kms.Kms, reader db.Reader, writer db.Writer, userId string, accountIds []string, opt ...Option) error {
	if repoKms == nil {
		return fmt.Errorf("associate user with accounts: kms is nil: %w", db.ErrInvalidParameter)
	}
	if reader == nil {
		return fmt.Errorf("associate user with accounts: db reader is nil: %w", db.ErrInvalidParameter)
	}
	if writer == nil {
		return fmt.Errorf("associate user with accounts: db writer is nil: %w", db.ErrInvalidParameter)
	}
	if userId == "" {
		return fmt.Errorf("associate user with accounts: user id is empty: %w", db.ErrInvalidParameter)
	}
	if len(accountIds) == 0 {
		return fmt.Errorf("associate user with accounts: missing account id %w", db.ErrInvalidParameter)
	}
	authAccounts := make([]*authAccount, 0, len(accountIds))
	for _, accountId := range accountIds {
		acct := allocAccount()
		acct.PublicId = accountId
		err := reader.LookupByPublicId(context.Background(), &acct)
		if err != nil {
			return fmt.Errorf("associate user with accounts: unable to lookup account %s: %w", accountId, err)
		}
		if acct.IamUserId != "" && acct.IamUserId != userId {
			return fmt.Errorf("associate user with accounts: %s account is associated with a user %s: %w", accountId, acct.IamUserId, db.ErrInvalidParameter)
		}
		authAccounts = append(authAccounts, &acct)
	}

	for _, aa := range authAccounts {
		// wrapper could be different for each authAccount depending on it's scope
		oplogWrapper, err := repoKms.GetWrapper(ctx, aa.GetScopeId(), kms.KeyPurposeOplog)
		if err != nil {
			return fmt.Errorf("associate user with accounts: unable to get oplog wrapper: %w", err)
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
			return fmt.Errorf("associate user with accouts: failed to associate %s account: %w", aa.PublicId, err)
		}
		if updatedRows == 0 {
			return fmt.Errorf("associate user with accounts: failed to associate %s account: it is already associated with another user", aa.PublicId)
		}
		if updatedRows > 1 {
			return fmt.Errorf("associate user with accounts: failed to associate %s account: would have updated too many accounts %d", aa.PublicId, updatedRows)
		}
	}
	return nil
}

// dissociateUserFromAccounts will dissociate a user with its existing accounts
// (accountIds). An error is returned if account is associated with a different
// user.  No options are currently supported.
func dissociateUserFromAccounts(ctx context.Context, repoKms *kms.Kms, reader db.Reader, writer db.Writer, userId string, accountIds []string, opt ...Option) error {
	if repoKms == nil {
		return fmt.Errorf("dissociate user from accounts: kms is nil: %w", db.ErrInvalidParameter)
	}
	if reader == nil {
		return fmt.Errorf("dissociate user from accounts: db reader is nil: %w", db.ErrInvalidParameter)
	}
	if writer == nil {
		return fmt.Errorf("dissociate user from accounts: db writer is nil: %w", db.ErrInvalidParameter)
	}
	if userId == "" {
		return fmt.Errorf("dissociate user from accounts: missing user public id %w", db.ErrInvalidParameter)
	}
	if len(accountIds) == 0 {
		return fmt.Errorf("dissociate user from accounts: missing account id %w", db.ErrInvalidParameter)
	}
	authAccounts := make([]*authAccount, 0, len(accountIds))
	for _, accountId := range accountIds {
		acct := allocAccount()
		acct.PublicId = accountId
		err := reader.LookupByPublicId(context.Background(), &acct)
		if err != nil {
			return fmt.Errorf("dissociate user from accounts: unable to lookup account %s: %w", accountId, err)
		}
		if acct.IamUserId != userId {
			return fmt.Errorf("dissociate user from accounts: %s account is not associated with user %s: %w", accountId, userId, db.ErrInvalidParameter)
		}
		authAccounts = append(authAccounts, &acct)
	}

	for _, aa := range authAccounts {
		// wrapper could be different for each authAccount depending on it's scope
		oplogWrapper, err := repoKms.GetWrapper(ctx, aa.GetScopeId(), kms.KeyPurposeOplog)
		if err != nil {
			return fmt.Errorf("dissociate user from accounts: unable to get oplog wrapper: %w", err)
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
			return fmt.Errorf("dissociate user from accounts: failed to disassociate %s account: %w", aa.PublicId, err)
		}
		if updatedRows == 0 {
			return fmt.Errorf("dissociate user from accounts: failed to disassociate %s account: it is associated with another user", aa.PublicId)
		}
		if updatedRows > 1 {
			return fmt.Errorf("dissociate user from accounts: failed to disassociate %s account: would have updated too many accounts %d", aa.PublicId, updatedRows)
		}
	}
	return nil
}

// associationChanges returns two slices: accounts to associate and disassociate
func associationChanges(ctx context.Context, reader db.Reader, userId string, accountIds []string) ([]string, []string, error) {
	var inClauseSpots []string
	// starts at 2 because there is already a $1 in the query
	for i := 2; i < len(accountIds)+2; i++ {
		inClauseSpots = append(inClauseSpots, fmt.Sprintf("$%d", i))
	}
	inClause := strings.Join(inClauseSpots, ",")
	if inClause == "" {
		inClause = "''"
	}
	query := fmt.Sprintf(accountChangesQuery, inClause)

	var params []interface{}
	params = append(params, userId)
	for _, v := range accountIds {
		params = append(params, v)
	}
	rows, err := reader.Query(query, params)
	if err != nil {
		return nil, nil, fmt.Errorf("changes: query failed: %w", err)
	}
	defer rows.Close()

	type change struct {
		Action    string
		AccountId string
	}
	var changes []*change
	for rows.Next() {
		var chg change
		if err := reader.ScanRows(rows, &chg); err != nil {
			return nil, nil, fmt.Errorf("changes: scan row failed: %w", err)
		}
		changes = append(changes, &chg)
	}
	var associateIds, disassociateIds []string
	for _, c := range changes {
		if c.AccountId == "" {
			return nil, nil, fmt.Errorf("changes: missing account id in change result")
		}
		switch c.Action {
		case "associate":
			associateIds = append(associateIds, c.AccountId)
		case "disassociate":
			disassociateIds = append(disassociateIds, c.AccountId)
		default:
			return nil, nil, fmt.Errorf("changes: unknown action %s for %s", c.Action, c.AccountId)
		}

	}
	return associateIds, disassociateIds, nil
}
