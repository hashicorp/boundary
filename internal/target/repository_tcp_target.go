package target

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateRootKeyVersion inserts into the repository and returns the new root key
// version with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateTcpTarget(ctx context.Context, keyWrapper wrapping.Wrapper, target *TcpTarget, opt ...Option) (Target, error) {
	if keyWrapper == nil {
		return nil, fmt.Errorf("create tcp target: missing key wrapper: %w", db.ErrNilParameter)
	}
	if target == nil {
		return nil, fmt.Errorf("create tcp target: missing target: %w", db.ErrNilParameter)
	}
	if target.TcpTarget == nil {
		return nil, fmt.Errorf("create tcp target: missing target store: %w", db.ErrNilParameter)
	}
	if target.ScopeId == "" {
		return nil, fmt.Errorf("create tcp target: scope id empty: %w", db.ErrInvalidParameter)
	}
	if target.Name == "" {
		return nil, fmt.Errorf("create tcp target: name empty: %w", db.ErrInvalidParameter)
	}
	if target.PublicId != "" {
		return nil, fmt.Errorf("create tcp target: public id not empty: %w", db.ErrInvalidParameter)

	}
	id, err := newTcpId()
	if err != nil {
		return nil, fmt.Errorf("create tcp target: %w", err)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, target.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("create tcp target: unable to get oplog wrapper: %w", err)
	}
	t := target.Clone().(*TcpTarget)
	t.PublicId = id

	metadata := t.oplog(oplog.OpType_OP_TYPE_CREATE)
	var returnedTarget interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedTarget = t.Clone()
			// no oplog entries for root key version
			if err := w.Create(ctx, returnedTarget, db.WithOplog(oplogWrapper, metadata)); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create tcp target: %w for %s root key id", err, t.PublicId)
	}
	return returnedTarget.(*TcpTarget), err
}
