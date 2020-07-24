package password

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// CreateAccount inserts a into the repository and returns a new
// Account containing the account's PublicId. a is not changed. a must
// contain a valid AuthMethodId. a must not contain a PublicId. The PublicId is
// generated and assigned by this method.
//
// Both a.Name and a.Description are optional. If a.Name is set, it must be
// unique within a.AuthMethodId.
func (r *Repository) CreateAccount(ctx context.Context, a *Account, opt ...Option) (*Account, error) {
	if a == nil {
		return nil, fmt.Errorf("create: password account: %w", db.ErrNilParameter)
	}
	if a.Account == nil {
		return nil, fmt.Errorf("create: password account: embedded Account: %w", db.ErrNilParameter)
	}
	if a.AuthMethodId == "" {
		return nil, fmt.Errorf("create: password account: no auth method id: %w", db.ErrInvalidParameter)
	}
	if a.PublicId != "" {
		return nil, fmt.Errorf("create: password account: public id not empty: %w", db.ErrInvalidParameter)
	}
	if !validUserName(a.UserName) {
		return nil, fmt.Errorf("create: password account: invalid user name: %w", db.ErrInvalidParameter)
	}

	a = a.clone()
	id, err := newAccountId()
	if err != nil {
		return nil, fmt.Errorf("create: password account: %w", err)
	}
	a.PublicId = id

	var newAccount *Account
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newAccount = a.clone()
			if err := w.Create(ctx, newAccount, db.WithOplog(r.wrapper, a.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return err
			}

			return nil
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create: password account: in auth method: %s: name %s already exists: %w",
				a.AuthMethodId, a.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create: password account: in auth method: %s: %w", a.AuthMethodId, err)
	}
	return newAccount, nil
}

var reInvalidUserName = regexp.MustCompile("[^a-z0-9.]")

func validUserName(u string) bool {
	if u == "" {
		return false
	}
	return !reInvalidUserName.Match([]byte(u))
}
