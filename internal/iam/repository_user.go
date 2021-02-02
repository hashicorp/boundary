package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// CreateUser will create a user in the repository and return the written user
func (r *Repository) CreateUser(ctx context.Context, user *User, opt ...Option) (*User, error) {
	const op = "iam.(Repository).CreateUser"
	if user == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing user")
	}
	if user.PublicId != "" {
		return nil, errors.New(errors.InvalidParameter, op, "public id is not empty")
	}
	u := user.Clone().(*User)

	opts := getOpts(opt...)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, UserPrefix+"_") {
			return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("passed-in public ID %q has wrong prefix, should be %q", opts.withPublicId, UserPrefix))
		}
		u.PublicId = opts.withPublicId
	} else {
		id, err := newUserId()
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		u.PublicId = id
	}

	resource, err := r.create(ctx, u)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.New(errors.NotUnique, op, fmt.Sprintf("user %s already exists in org %s", user.Name, user.ScopeId))
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("for %s", u.PublicId)))
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
		return nil, nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing user")
	}
	if user.PublicId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing public id")
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, nil, db.NoRowsAffected, errors.New(errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
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
		return nil, nil, db.NoRowsAffected, errors.E(errors.WithCode(errors.EmptyFieldMask), errors.WithOp(op))
	}

	u := user.Clone().(*User)
	metadata, err := r.stdMetadata(ctx, u)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(err, op)
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
		return nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get scope"))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
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
				return errors.Wrap(err, op)
			}
			if rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New(errors.MultipleRecords, op, "more than 1 resource would have been updated")
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
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current account ids after update"))
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, db.NoRowsAffected, errors.New(errors.NotUnique, op, fmt.Sprintf("user %s already exists in org %s", user.Name, user.ScopeId))
		}
		return nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("for %s", user.PublicId)))
	}
	return returnedUser, currentAccountIds, rowsUpdated, nil
}

// LookupUser will look up a user and its associated account ids in the
// repository.  If the user is not found, it will return nil, nil, nil.
func (r *Repository) LookupUser(ctx context.Context, userId string, _ ...Option) (*User, []string, error) {
	const op = "iam.(Repository).LookupUser"
	if userId == "" {
		return nil, nil, errors.New(errors.InvalidParameter, op, "missing public id")
	}

	user := allocUser()
	user.PublicId = userId
	if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil
		}
		return nil, nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("for %s", userId)))
	}
	currentAccountIds, err := r.ListUserAccounts(ctx, userId)
	if err != nil {
		return nil, nil, errors.Wrap(err, op, errors.WithMsg("unable to retrieve current account ids"))
	}
	return &user, currentAccountIds, nil
}

// DeleteUser will delete a user from the repository
func (r *Repository) DeleteUser(ctx context.Context, withPublicId string, _ ...Option) (int, error) {
	const op = "iam.(Repository).DeleteUser"
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing public id")
	}
	user := allocUser()
	user.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("for %s", withPublicId)))
	}
	rowsDeleted, err := r.delete(ctx, &user)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("for %s", withPublicId)))
	}
	return rowsDeleted, nil
}

// ListUsers lists users in the given scopes and supports the WithLimit option.
func (r *Repository) ListUsers(ctx context.Context, withScopeIds []string, opt ...Option) ([]*User, error) {
	const op = "iam.(Repository).ListUsers"
	if len(withScopeIds) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing scope id")
	}
	var users []*User
	err := r.list(ctx, &users, "scope_id in (?)", []interface{}{withScopeIds}, opt...)
	if err != nil {
		return nil, errors.Wrap(err, op)
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
	const op = "iam.(Repository).LookupUserWithLogin"
	opts := getOpts(opt...)
	if accountId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing account id")
	}
	u, err := r.getUserWithAccount(ctx, accountId)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	if u != nil {
		return u, nil
	}
	if !opts.withAutoVivify {
		return nil, errors.New(errors.RecordNotFound, op, fmt.Sprintf("user not found for account %s", accountId))
	}

	acct := allocAccount()
	acct.PublicId = accountId
	err = r.reader.LookupByPublicId(context.Background(), &acct)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to lookup account %s", accountId)))
	}

	metadata := oplog.Metadata{
		"resource-public-id": []string{accountId},
		"scope-id":           []string{acct.ScopeId},
		"scope-type":         []string{scope.Org.String()},
		"resource-type":      []string{"auth-account"},
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, acct.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
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
				return errors.Wrap(err, op)
			}
			obtainedUser, err = NewUser(acct.ScopeId, opt...)
			if err != nil {
				return errors.Wrap(err, op)
			}
			id, err := newUserId()
			if err != nil {
				return errors.Wrap(err, op)
			}
			var createMsg oplog.Message
			obtainedUser.PublicId = id
			err = w.Create(ctx, obtainedUser, db.NewOplogMsg(&createMsg))
			if err != nil {
				return errors.Wrap(err, op)
			}
			msgs = append(msgs, &createMsg)

			var updateMsg oplog.Message
			updateAcct := acct.Clone().(*authAccount)
			updateAcct.IamUserId = id
			updatedRows, err := w.Update(ctx, updateAcct, []string{"IamUserId"}, nil, db.NewOplogMsg(&updateMsg))
			if err != nil {
				return errors.Wrap(err, op)
			}
			if updatedRows != 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("account update affected %d rows", updatedRows))
			}
			msgs = append(msgs, &updateMsg)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return obtainedUser, nil
}

func (r *Repository) getUserWithAccount(ctx context.Context, withAccountId string, _ ...Option) (*User, error) {
	const op = "iam.(Repository).getUserWithAccount"
	if withAccountId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing account id")
	}
	rows, err := r.reader.Query(ctx, whereUserAccount, []interface{}{withAccountId})
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to query account %s", withAccountId)))
	}
	defer rows.Close()
	u := allocUser()
	if rows.Next() {
		err = r.reader.ScanRows(rows, &u)
		if err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to scan rows for account %s", withAccountId)))
		}
	} else {
		if err := rows.Err(); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to get next account"))
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
		return nil, errors.New(errors.InvalidParameter, op, "missing user id")
	}
	var accounts []*authAccount
	if err := r.list(ctx, &accounts, "iam_user_id = ?", []interface{}{userId}, opt...); err != nil {
		return nil, errors.Wrap(err, op)
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
		return nil, errors.New(errors.InvalidParameter, op, "missing user id")
	}
	if userVersion == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing user version")
	}
	if len(accountIds) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing account ids")
	}

	user := allocUser()
	user.PublicId = userId

	err := r.reader.LookupById(ctx, &user)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to lookup user %s", userId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, user.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var currentAccountIds []string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			userTicket, err := w.GetTicket(&user)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedUser := allocUser()
			updatedUser.PublicId = userId
			updatedUser.Version = userVersion + 1
			var userOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedUser, []string{"Version"}, nil, db.NewOplogMsg(&userOplogMsg), db.WithVersion(&userVersion))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get user version"))
			}
			if rowsUpdated != 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated user and %d rows updated", rowsUpdated))
			}
			if err := associateUserWithAccounts(ctx, r.kms, reader, w, user.PublicId, accountIds); err != nil {
				return errors.Wrap(err, op)
			}
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{user.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-public-id": []string{user.PublicId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, userTicket, metadata, []*oplog.Message{&userOplogMsg}); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
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
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current account ids after adds"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
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
		return nil, errors.New(errors.InvalidParameter, op, "missing public id")
	}
	if userVersion == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing user version")
	}
	if len(accountIds) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing account ids")
	}

	user := allocUser()
	user.PublicId = userId
	err := r.reader.LookupById(ctx, &user)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to lookup user %s", userId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, user.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var currentAccountIds []string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			userTicket, err := w.GetTicket(&user)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedUser := allocUser()
			updatedUser.PublicId = userId
			updatedUser.Version = userVersion + 1
			var userOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedUser, []string{"Version"}, nil, db.NewOplogMsg(&userOplogMsg), db.WithVersion(&userVersion))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to update user version"))
			}
			if rowsUpdated != 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated user and %d rows updated", rowsUpdated))
			}
			if err := dissociateUserFromAccounts(ctx, r.kms, reader, w, user.PublicId, accountIds); err != nil {
				return errors.Wrap(err, op)
			}
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{user.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-public-id": []string{user.PublicId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, userTicket, metadata, []*oplog.Message{&userOplogMsg}); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
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
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current account ids after adds"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
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
		return nil, errors.New(errors.InvalidParameter, op, "missing public id")
	}
	if userVersion == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing version")
	}

	user := allocUser()
	user.PublicId = userId
	err := r.reader.LookupById(ctx, &user)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to lookup user %s", userId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, user.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	var currentAccountIds []string
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			associateIds, disassociateIds, err := associationChanges(ctx, reader, userId, accountIds)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to determine changes"))
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
					return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current account ids after set"))
				}
				return nil
			}
			userTicket, err := w.GetTicket(&user)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedUser := allocUser()
			updatedUser.PublicId = userId
			updatedUser.Version = userVersion + 1
			var userOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedUser, []string{"Version"}, nil, db.NewOplogMsg(&userOplogMsg), db.WithVersion(&userVersion))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to update user version"))
			}
			if rowsUpdated != 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated user and %d rows updated", rowsUpdated))
			}

			if len(associateIds) > 0 {
				if err := associateUserWithAccounts(ctx, r.kms, reader, w, userId, associateIds); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to associate ids"))
				}
			}

			if len(disassociateIds) > 0 {
				if err := dissociateUserFromAccounts(ctx, r.kms, reader, w, userId, disassociateIds); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to disassociate ids"))
				}
			}

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{user.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-public-id": []string{userId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, userTicket, metadata, []*oplog.Message{&userOplogMsg}); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
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
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current account ids after set"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return currentAccountIds, nil
}

// associateUserWithAccounts will associate the accounts (accountIds) with
// the user (userId) within the writer's database
func associateUserWithAccounts(ctx context.Context, repoKms *kms.Kms, reader db.Reader, writer db.Writer, userId string, accountIds []string, _ ...Option) error {
	const op = "iam.associateUserWithAccounts"
	if repoKms == nil {
		return errors.New(errors.InvalidParameter, op, "nil kms")
	}
	if reader == nil {
		return errors.New(errors.InvalidParameter, op, "nil reader")
	}
	if writer == nil {
		return errors.New(errors.InvalidParameter, op, "nil writer")
	}
	if userId == "" {
		return errors.New(errors.InvalidParameter, op, "missing user id")
	}
	if len(accountIds) == 0 {
		return errors.New(errors.InvalidParameter, op, "missing account ids")
	}
	authAccounts := make([]*authAccount, 0, len(accountIds))
	for _, accountId := range accountIds {
		acct := allocAccount()
		acct.PublicId = accountId
		err := reader.LookupByPublicId(context.Background(), &acct)
		if err != nil {
			return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to lookup account %s", accountId)))
		}
		if acct.IamUserId != "" && acct.IamUserId != userId {
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s account is associated with a user %s", accountId, acct.IamUserId))
		}
		authAccounts = append(authAccounts, &acct)
	}

	for _, aa := range authAccounts {
		// wrapper could be different for each authAccount depending on it's scope
		oplogWrapper, err := repoKms.GetWrapper(ctx, aa.GetScopeId(), kms.KeyPurposeOplog)
		if err != nil {
			return errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
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
			return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed to associate %s account", aa.PublicId)))
		}
		if updatedRows == 0 {
			return errors.New(errors.MultipleRecords, op, fmt.Sprintf("failed to associate %s account: it is already associated with another user", aa.PublicId))
		}
		if updatedRows > 1 {
			return errors.New(errors.MultipleRecords, op, fmt.Sprintf("failed to associate %s account: would have updated too many accounts %d", aa.PublicId, updatedRows))
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
		return errors.New(errors.InvalidParameter, op, "nil kms")
	}
	if reader == nil {
		return errors.New(errors.InvalidParameter, op, "nil reader")
	}
	if writer == nil {
		return errors.New(errors.InvalidParameter, op, "nil writer")
	}
	if userId == "" {
		return errors.New(errors.InvalidParameter, op, "missing public id")
	}
	if len(accountIds) == 0 {
		return errors.New(errors.InvalidParameter, op, "missing account ids")
	}
	authAccounts := make([]*authAccount, 0, len(accountIds))
	for _, accountId := range accountIds {
		acct := allocAccount()
		acct.PublicId = accountId
		err := reader.LookupByPublicId(context.Background(), &acct)
		if err != nil {
			return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to lookup account %s", accountId)))
		}
		if acct.IamUserId != userId {
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s account is not associated with user %s", accountId, userId))
		}
		authAccounts = append(authAccounts, &acct)
	}

	for _, aa := range authAccounts {
		// wrapper could be different for each authAccount depending on it's scope
		oplogWrapper, err := repoKms.GetWrapper(ctx, aa.GetScopeId(), kms.KeyPurposeOplog)
		if err != nil {
			return errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
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
			return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed to disassociate %s account", aa.PublicId)))
		}
		if updatedRows == 0 {
			return errors.New(errors.MultipleRecords, op, fmt.Sprintf("failed to disassociate %s account: it is already associated with another user", aa.PublicId))
		}
		if updatedRows > 1 {
			return errors.New(errors.MultipleRecords, op, fmt.Sprintf("failed to disassociate %s account: would have updated too many accounts %d", aa.PublicId, updatedRows))
		}
	}
	return nil
}

// associationChanges returns two slices: accounts to associate and disassociate
func associationChanges(ctx context.Context, reader db.Reader, userId string, accountIds []string) ([]string, []string, error) {
	const op = "iam.associationChanges"
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
	rows, err := reader.Query(ctx, query, params)
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
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
			return nil, nil, errors.Wrap(err, op)
		}
		changes = append(changes, &chg)
	}
	var associateIds, disassociateIds []string
	for _, c := range changes {
		if c.AccountId == "" {
			return nil, nil, errors.New(errors.InvalidParameter, op, "missing account id in change result")
		}
		switch c.Action {
		case "associate":
			associateIds = append(associateIds, c.AccountId)
		case "disassociate":
			disassociateIds = append(disassociateIds, c.AccountId)
		default:
			return nil, nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("unknown action %s for %s", c.Action, c.AccountId))
		}
	}
	return associateIds, disassociateIds, nil
}
