package servers

import (
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

const (
	// DefaultLiveness is the setting that controls the server "liveness" time,
	// or the maximum allowable time that a worker can't send a status update to
	// the controller for. After this, the server is considered dead, and it will
	// be taken out of the rotation for allowable workers for connections, and
	// connections will possibly start to be terminated and marked as closed
	// depending on the grace period setting (see
	// base.Server.StatusGracePeriodDuration). This value serves as the default
	// and minimum allowable setting for the grace period.
	DefaultLiveness = 15 * time.Second
)

// Repository is the servers database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

// NewRepository creates a new servers Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms) (*Repository, error) {
	const op = "servers.NewRepository"
	if r == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil kms")
	}
	return &Repository{
		reader: r,
		writer: w,
		kms:    kms,
	}, nil
}
