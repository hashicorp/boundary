package session

import (
	"context"
	"errors"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
)

// Clonable provides a cloning interface
type Cloneable interface {
	Clone() interface{}
}

// Repository is the target database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new session Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if kms == nil {
		return nil, errors.New("error creating db repository with nil kms")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.withLimit,
	}, nil
}

func (r *Repository) CreateSession(ctx context.Context, s *Session, opt ...Option) (*Session, error) {
	panic("not implemented")
}

func (r *Repository) LookupSession(ctx context.Context, publicId string, opt ...Option) (*Session, []*State, error) {
	panic("not implemented")
}

func (r *Repository) ListSessions(ctx context.Context, opt ...Option) ([]*Session, error) {
	panic("not implemented")
}

func (r *Repository) DeleteSession(ctx context.Context, publicId string, opt ...Option) (int, error) {
	panic("not implemented")
}

func (r *Repository) UpdateSession(ctx context.Context, s *Session, version uint32, fieldMaskPaths []string, opt ...Option) (*Session, []*State, int, error) {
	panic("not implemented")
}

func (r *Repository) UpdateState(ctx context.Context, sessionId string, sessionVersion uint32, s Status, opt ...Option) (*Session, []*State, int, error) {
	panic("not implemented")
}
