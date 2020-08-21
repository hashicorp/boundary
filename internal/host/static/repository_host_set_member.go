package static

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

// ListSetMembers returns a slice of all host set members in setId.
func (r *Repository) ListSetMembers(ctx context.Context, setId string, opt ...Option) ([]*HostSetMember, error) {
	if setId == "" {
		return nil, fmt.Errorf("list: static host set members: missing set id: %w", db.ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var members []*HostSetMember
	err := r.reader.SearchWhere(ctx, &members, "set_id = ?", []interface{}{setId}, db.WithLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list: static host set members: %w", err)
	}
	return members, nil
}

// AddSetMembers adds hostIds to setId in the repository. It returns a
// slice of all host set members in setId. A host must belong to the same
// catalog as the set to be added. The version must match the current
// version of the setId in the repository.
func (r *Repository) AddSetMembers(ctx context.Context, scopeId string, setId string, version uint32, hostIds []string, opt ...Option) ([]*HostSetMember, error) {
	panic("not implemented")
}

// DeleteSetMembers deletes hostIds from setId in the repository. It
// returns the number of hosts deleted from the set. The version must match
// the current version of the setId in the repository.
func (r *Repository) DeleteSetMembers(ctx context.Context, scopeId string, setId string, version uint32, hostIds []string, opt ...Option) (int, error) {
	panic("not implemented")
}

// SetSetMembers replaces the hosts in setId with hostIds in the
// repository. It returns a slice of all host set members in setId. A host
// must belong to the same catalog as the set to be added. The version must
// match the current version of the setId in the repository.
func (r *Repository) SetSetMembers(ctx context.Context, scopeId string, setId string, version uint32, hostIds []string, opt ...Option) ([]*HostSetMember, error) {
	panic("not implemented")
}
