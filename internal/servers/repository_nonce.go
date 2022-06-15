package servers

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

type Nonce struct {
	Nonce   string
	Purpose string
}

// TableName returns the table name.
func (n *Nonce) TableName() string {
	return "nonce"
}

const (
	NoncePurposeRecovery   = "recovery"
	NoncePurposeWorkerAuth = "worker-auth"
)

// AddNonce adds a nonce
func (r *Repository) AddNonce(ctx context.Context, nonce, purpose string, opt ...Option) error {
	const op = "servers.AddNonce"
	if nonce == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "empty nonce")
	}
	switch purpose {
	case NoncePurposeRecovery, NoncePurposeWorkerAuth:
	case "":
		return errors.New(ctx, errors.InvalidParameter, op, "empty nonce purpose")
	default:
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown nonce purpose %q", purpose))
	}
	if err := r.writer.Create(ctx, &Nonce{
		Nonce:   nonce,
		Purpose: purpose,
	}); err != nil {
		return errors.Wrap(ctx, err, op+":Insertion")
	}
	return nil
}

// CleanupNonces removes nonces that no longer need to be stored
func (r *Repository) CleanupNonces(ctx context.Context, opt ...Option) (int, error) {
	// Use the largest validity period out of the various nonces we're looking at
	maxDuration := globals.RecoveryTokenValidityPeriod
	if globals.WorkerAuthNonceValidityPeriod > maxDuration {
		maxDuration = globals.WorkerAuthNonceValidityPeriod
	}
	// If something was inserted before 3x the actual validity period, clean it out
	endTime := time.Now().Add(-3 * maxDuration)

	rows, err := r.writer.Delete(ctx, &Nonce{}, db.WithWhere(deleteWhereCreateTimeSql, endTime))
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, "servers.CleanupNonces")
	}
	return rows, nil
}

// ListNonces lists nonces. Used only for tests at the moment.
func (r *Repository) ListNonces(ctx context.Context, purpose string, opt ...Option) ([]*Nonce, error) {
	var nonces []*Nonce
	if err := r.reader.SearchWhere(ctx, &nonces, "purpose = ?", []interface{}{purpose}, db.WithLimit(-1)); err != nil {
		return nil, errors.Wrap(ctx, err, "servers.ListNonces")
	}
	return nonces, nil
}
