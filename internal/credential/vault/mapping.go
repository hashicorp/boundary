package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
)

// Mapping represents the mapping a Vault credential library should use to
// Issue a strongly typed Vault credential
type Mapping interface {
	oplog(op oplog.OpType) oplog.Metadata
}

func newMapping(ctx context.Context, m credential.Mapping, lId string) (Mapping, error) {
	const op = "vault.newMapping"
	if lId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing library id")
	}
	if m == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing mapping")
	}
	switch vm := m.(type) {
	case credential.UserPasswordMapping:
		if vm.Username == "" {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "missing username")
		}
		if vm.Password == "" {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "missing password")
		}

		u := NewUserPasswordMap(lId, vm.Username, vm.Password)
		id, err := newUsernamePasswordMapId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		u.PrivateId = id

		return u, nil
	default:
		return nil, errors.New(ctx, errors.InvalidMapping, op, fmt.Sprintf("unsupported mapping: %T", vm))
	}
}
