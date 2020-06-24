package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
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
			return nil, fmt.Errorf("create user: user %s already exists in organization %s", user.Name, user.ScopeId)
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
func (r *Repository) UpdateUser(ctx context.Context, user *User, fieldMaskPaths []string, opt ...Option) (*User, int, error) {
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
	dbMask, nullFields = buildUpdatePaths(
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
	resource, rowsUpdated, err := r.update(ctx, u.(*User), dbMask, nullFields)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update user: user %s already exists in organization %s", user.Name, user.ScopeId)
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

// ListUsers in an organization and supports the WithLimit option.
func (r *Repository) ListUsers(ctx context.Context, withOrganizationId string, opt ...Option) ([]*User, error) {
	if withOrganizationId == "" {
		return nil, fmt.Errorf("list users: missing organization id %w", db.ErrInvalidParameter)
	}
	var users []*User
	err := r.list(ctx, &users, "scope_id = ?", []interface{}{withOrganizationId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// ObtainUserWithLogin will attempt to lookup the user within the scope and
// authMethod with a matching auth account id and return the user if found.  If
// a user is not found then a new User will be created in the scope provided and
// associated the authMethod and authAccountId provided.  If a new user is
// created, then the WithName and WithDescription options are supported.
func (r *Repository) ObtainUserWithLogin(ctx context.Context, withScope, withAuthMethodId, withAuthAccountId string, opt ...Option) (*User, error) {
	if withScope == "" {
		return nil, fmt.Errorf("create user with login: missing scope id %w", db.ErrInvalidParameter)
	}
	if withAuthMethodId == "" {
		return nil, fmt.Errorf("create user with login: missing auth method id %w", db.ErrInvalidParameter)
	}
	if withAuthAccountId == "" {
		return nil, fmt.Errorf("create user with login: missing auth account id %w", db.ErrInvalidParameter)

	}
	ok, err := r.validateAuthMethodId(ctx, withScope, withAuthMethodId)
	if err != nil {
		return nil, fmt.Errorf("create user with login: unable to validate auth method %s in scope %s: %w", withAuthMethodId, withScope, err)
	}
	if !ok {
		return nil, fmt.Errorf("create user with login: auth method id %s in scope %s is not valid: %w", withAuthMethodId, withScope, db.ErrInvalidParameter)
	}
	acct := allocAuthAccount()
	err = r.reader.LookupWhere(context.Background(), &acct, "public_id = ? and auth_method_id = ?", withAuthAccountId, withAuthMethodId)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, fmt.Errorf("create user with login: unable to search for auth account %s in auth method %s: %w", withAuthAccountId, withAuthMethodId, db.ErrInvalidParameter)
		}
		return nil, fmt.Errorf("create user with login: unable to search for auth account %s in auth method %s: %w", withAuthAccountId, withAuthMethodId, err)
	}
	if acct.IamUserId != "" {
		u, err := r.LookupUser(ctx, acct.IamUserId)
		if err != nil {
			return nil, fmt.Errorf("create user with login: unable to lookup user %s for auth account %s", acct.IamUserId, acct.PublicId)
		}
		// LookupUser will return a nil user and no error if the user is not found.
		if u == nil {
			return nil, nil
		}
		if u.ScopeId != withScope {
			return nil, fmt.Errorf("create user with login: user scope %s doesn't match scope %s: %w", u.ScopeId, withScope, db.ErrInvalidParameter)
		}
		return u, nil
	}

	s, err := r.LookupScope(ctx, withScope)
	if err != nil {
		return nil, fmt.Errorf("create user with login: %w", err)
	}
	metadata := oplog.Metadata{
		"resource-public-id": []string{acct.PublicId},
		"scope-id":           []string{s.PublicId},
		"scope-type":         []string{s.Type},
		"resource-type":      []string{"auth-account"},
	}

	// We will create a new user and associate the user with the auth account
	// within one retryable transaction using writer.DoTx
	var obtainedUser *User
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := []*oplog.Message{}
			ticket, err := w.GetTicket(&acct)
			if err != nil {
				return err
			}
			obtainedUser, err = NewUser(withScope, opt...)
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
			updateAcct := acct.Clone().(*AuthAccount)
			updateAcct.IamUserId = id
			updatedRows, err := w.Update(ctx, updateAcct, []string{"IamUserId"}, nil, db.NewOplogMsg(&updateMsg))
			if err != nil {
				return err
			}
			if updatedRows != 1 {
				return fmt.Errorf("auth account update affected %d rows", updatedRows)
			}
			msgs = append(msgs, &updateMsg)
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, ticket, metadata, msgs); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create user with login: unable to associate user and account: %w", err)
	}
	return obtainedUser, nil
}

// LookupUserWithLogin within the scope and authMethod with a matching
// authAccountId. The function will return nil, nil when a user is not found
// matching the provided criteria. No options are supported.
func (r *Repository) LookupUserWithLogin(ctx context.Context, withScope, withAuthMethodId, withAuthAccountId string, opt ...Option) (*User, error) {
	if withScope == "" {
		return nil, fmt.Errorf("lookup user with login: missing scope id %w", db.ErrInvalidParameter)
	}
	if withAuthMethodId == "" {
		return nil, fmt.Errorf("lookup user with login: missing auth method id %w", db.ErrInvalidParameter)
	}
	if withAuthAccountId == "" {
		return nil, fmt.Errorf("lookup user with login: missing auth account id %w", db.ErrInvalidParameter)
	}
	ok, err := r.validateAuthMethodId(ctx, withScope, withAuthMethodId)
	if err != nil {
		return nil, fmt.Errorf("lookup user with login: unable to validate auth method %s in scope %s: %w", withAuthMethodId, withScope, err)
	}
	if !ok {
		return nil, fmt.Errorf("lookup user with login: auth method id %s in scope %s is not valid: %w", withAuthMethodId, withScope, db.ErrInvalidParameter)
	}
	acct := allocAuthAccount()
	err = r.reader.LookupWhere(context.Background(), &acct, "public_id = ? and auth_method_id = ?", withAuthAccountId, withAuthMethodId)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, fmt.Errorf("lookup user with login: unable to search for auth account %s in auth method %s: %w", withAuthAccountId, withAuthMethodId, db.ErrInvalidParameter)
		}
		return nil, fmt.Errorf("lookup user with login: unable to search for auth account %s in auth method %s: %w", withAuthAccountId, withAuthMethodId, err)
	}
	if acct.IamUserId == "" {
		return nil, nil
	}
	u, err := r.LookupUser(ctx, acct.IamUserId)
	if err != nil {
		return nil, fmt.Errorf("lookup user with login: unable to lookup user %s for auth account %s: %w", acct.IamUserId, acct.PublicId, err)
	}
	if u.ScopeId != withScope {
		return nil, fmt.Errorf("lookup user with login: user scope %s doesn't match scope %s: %w", u.ScopeId, withScope, db.ErrInvalidParameter)
	}
	return u, nil
}

// TODO (jimlambrt 6/2020) replace the raw query with a Lookup using the auth
// method repo.
func (r *Repository) validateAuthMethodId(ctx context.Context, scopeId, authMethodId string) (bool, error) {
	if scopeId == "" {
		return false, fmt.Errorf("scope id is unset: %w", db.ErrInvalidParameter)
	}
	if authMethodId == "" {
		return false, fmt.Errorf("auth method id is unset: %w", db.ErrInvalidParameter)
	}
	const where = `select count(*) from auth_method where public_id = $1 and scope_id = $2`
	db, err := r.reader.DB()
	if err != nil {
		return false, err
	}
	var cnt int
	if err := db.QueryRow(where, authMethodId, scopeId).Scan(&cnt); err != nil {
		return false, err
	}
	if cnt == 0 {
		return false, nil
	}
	return true, nil
}
