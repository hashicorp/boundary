package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
	dbcommon "github.com/hashicorp/watchtower/internal/db/common"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/types/scope"
)

// CreateUser will create a user in the repository and return the written user
func (r *Repository) CreateUser(ctx context.Context, user *User, opt ...Option) (*User, error) {
	if user == nil {
		return nil, fmt.Errorf("create user: missing user %w", db.ErrNilParameter)
	}
	if user.PublicId != "" {
		return nil, fmt.Errorf("create user: public id is not empty %w", db.ErrInvalidParameter)
	}
	id, err := newUserId()
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	u := user.Clone()
	u.(*User).PublicId = id
	resource, err := r.create(ctx, u.(*User))
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create user: user %s already exists in org %s", user.Name, user.ScopeId)
		}
		return nil, fmt.Errorf("create user: %w for %s", err, u.(*User).PublicId)
	}
	return resource.(*User), err
}

// UpdateUser will update a user in the repository and return the written user.
// fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name and Description are the only updatable fields,
// If no updatable fields are included in the fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateUser(ctx context.Context, user *User, version uint32, fieldMaskPaths []string, opt ...Option) (*User, int, error) {
	if user == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update user: missing user %w", db.ErrNilParameter)
	}
	if user.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update user: missing user public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update user: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"name":        user.Name,
			"description": user.Description,
		},
		fieldMaskPaths,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update user: %w", db.ErrEmptyFieldMask)
	}

	u := user.Clone()
	resource, rowsUpdated, err := r.update(ctx, u.(*User), version, dbMask, nullFields, opt...)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update user: user %s already exists in org %s", user.Name, user.ScopeId)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update user: %w for %s", err, user.PublicId)
	}
	return resource.(*User), rowsUpdated, err
}

// LookupUser will look up a user in the repository.  If the user is not
// found, it will return nil, nil.
func (r *Repository) LookupUser(ctx context.Context, withPublicId string, opt ...Option) (*User, error) {
	if withPublicId == "" {
		return nil, fmt.Errorf("lookup user: missing public id %w", db.ErrNilParameter)
	}

	user := allocUser()
	user.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
		return nil, fmt.Errorf("lookup user: failed %w for %s", err, withPublicId)
	}
	return &user, nil
}

// DeleteUser will delete a user from the repository
func (r *Repository) DeleteUser(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete user: missing public id %w", db.ErrNilParameter)
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
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, ticket, metadata, msgs); err != nil {
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

// AssociateUserWithAccount will associate a user with an existing account.
// The account must not already be associated with a different user.  No
// options are currently supported.
func (r *Repository) AssociateUserWithAccount(ctx context.Context, userPublicId, accountId string, opt ...Option) (*User, *authAccount, error) {
	opts := getOpts(opt...)
	if userPublicId == "" {
		return nil, nil, fmt.Errorf("associate user with account: missing user public id %w", db.ErrInvalidParameter)
	}
	if accountId == "" {
		return nil, nil, fmt.Errorf("associate user with account: missing account id %w", db.ErrInvalidParameter)
	}

	user := allocUser()
	user.PublicId = userPublicId

	err := r.reader.LookupById(ctx, &user)
	if err != nil {
		return nil, nil, fmt.Errorf("associate user with account: unable to lookup user %s: %w", userPublicId, err)
	}

	acct := allocAccount()
	acct.PublicId = accountId
	err = r.reader.LookupByPublicId(context.Background(), &acct)
	if err != nil {
		return nil, nil, fmt.Errorf("associate user with account: unable to lookup account %s: %w", accountId, err)
	}
	// first, let's handle the case where the account is already
	// associated with the user, so we're done!
	if acct.IamUserId == userPublicId {
		return &user, &acct, nil
	}

	if !opts.withDisassociate {
		if acct.IamUserId != "" && acct.IamUserId != userPublicId {
			return nil, nil, fmt.Errorf("associate user with account: %s account is already associated with a user: %w", accountId, db.ErrInvalidParameter)
		}
	}

	var updatedAcct *authAccount

	// validate, associated the user with the account, and then read the
	// user back in the same tx for consistency.
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(txReader db.Reader, w db.Writer) error {

			metadata := oplog.Metadata{
				"resource-public-id": []string{accountId},
				"scope-id":           []string{acct.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-type":      []string{"auth-account"},
			}
			var updatedRows int
			updatedAcct = acct.Clone().(*authAccount)
			updatedAcct.IamUserId = userPublicId
			// we are using WithWhere to make sure the account is not
			// associated with a user (handling race conditions with concurrent
			// transactions)
			switch {
			case opts.withDisassociate:
				updatedRows, err = w.Update(ctx, updatedAcct, []string{"IamUserId"}, nil, db.WithOplog(r.wrapper, metadata), db.WithWhere("iam_user_id = ?", acct.IamUserId))
			default:
				//				updatedRows, err = w.Update(ctx, updatedAcct, []string{"IamUserId"}, nil, db.WithOplog(r.wrapper, metadata), db.WithWhere("iam_user_id is ?", gorm.Expr("NULL")))
				updatedRows, err = w.Update(ctx, updatedAcct, []string{"IamUserId"}, nil, db.WithOplog(r.wrapper, metadata), db.WithWhere("iam_user_id is NULL"))

			}
			if err != nil {
				return err
			}
			if updatedRows != 1 {
				return fmt.Errorf("account update affected %d rows", updatedRows)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("associate user with account: %w", err)
	}
	return &user, updatedAcct, nil
}

// DissociateUserWithAccount will dissociate a user with its existing account.
// An error is returned if account is associated with a different user.  No
// options are currently supported.
func (r *Repository) DissociateUserWithAccount(ctx context.Context, userPublicId, accountId string, opt ...Option) (*User, *authAccount, error) {
	if userPublicId == "" {
		return nil, nil, fmt.Errorf("dissociate user with account: missing user public id %w", db.ErrInvalidParameter)
	}
	if accountId == "" {
		return nil, nil, fmt.Errorf("dissociate user with account: missing account id %w", db.ErrInvalidParameter)
	}

	user := allocUser()
	user.PublicId = userPublicId
	err := r.reader.LookupById(ctx, &user)
	if err != nil {
		return nil, nil, fmt.Errorf("dissociate user with account: unable to lookup user %s: %w", userPublicId, err)
	}

	acct := allocAccount()
	acct.PublicId = accountId
	err = r.reader.LookupByPublicId(ctx, &acct)
	if err != nil {
		return nil, nil, fmt.Errorf("dissociate user with account: unable to lookup account %s: %w", accountId, err)
	}
	// first, let's handle the case where the account is not associated
	// with any user, so we're done!
	if acct.IamUserId == "" {
		return &user, &acct, nil
	}
	// before proceeding with an update, is the account associated with the different user?
	if acct.IamUserId != userPublicId {
		return nil, nil, fmt.Errorf("dissociate user with account: %s account is not associated with a user: %w", accountId, db.ErrInvalidParameter)
	}

	var updatedAcct *authAccount

	// validate, dissociate the user with the account and then read the user back in
	// the same tx for consistency.
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(txReader db.Reader, w db.Writer) error {
			metadata := oplog.Metadata{
				"resource-public-id": []string{accountId},
				"scope-id":           []string{acct.ScopeId},
				"scope-type":         []string{scope.Org.String()},
				"resource-type":      []string{"auth-account"},
			}
			updatedAcct = acct.Clone().(*authAccount)
			updatedAcct.IamUserId = ""
			// set the user id to null and use WithWhere to ensure that the auth
			// account is associated with the user (handling race conditions
			// with other concurrent transactions)
			updatedRows, err := w.Update(ctx, updatedAcct, nil, []string{"IamUserId"}, db.WithOplog(r.wrapper, metadata), db.WithWhere("iam_user_id = ?", userPublicId))
			if err != nil {
				return err
			}
			if updatedRows != 1 {
				return fmt.Errorf("account update affected %d rows", updatedRows)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dissociate user with account: %w", err)
	}
	return &user, updatedAcct, nil
}
