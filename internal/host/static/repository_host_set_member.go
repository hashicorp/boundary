package static

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

// ListSetMembers returns a slice of all hosts in setId.
func (r *Repository) ListSetMembers(ctx context.Context, setId string, opt ...Option) ([]*Host, error) {
	if setId == "" {
		return nil, fmt.Errorf("list: static host set members: missing set id: %w", db.ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	tx, err := r.reader.DB()
	if err != nil {
		return nil, fmt.Errorf("list: static host set members: %w", err)
	}

	var rows *sql.Rows
	switch {
	case limit > 0:
		rows, err = tx.Query(setMembersQueryLimit, setId, limit)
	default:
		rows, err = tx.Query(setMembersQueryNoLimit, setId)
	}
	if err != nil {
		return nil, fmt.Errorf("list: static host set members: %w", err)
	}
	defer rows.Close()

	var hosts []*Host

	for rows.Next() {
		var h Host
		if err := r.reader.ScanRows(rows, &h); err != nil {
			return nil, fmt.Errorf("list: static host set members: %w", err)
		}
		hosts = append(hosts, &h)
	}

	return hosts, nil
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
