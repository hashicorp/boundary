package session

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

// ListSessions will sessions.  Supports the WithLimit, WithScopeId and WithOrder options.
func (r *Repository) ListSessions(ctx context.Context, opt ...Option) ([]*Session, error) {
	opts := getOpts(opt...)
	var where []string
	var args []interface{}
	switch {
	case opts.withScopeId != "":
		where, args = append(where, "scope_id = ?"), append(args, opts.withScopeId)
	case opts.withUserId != "":
		where, args = append(where, "user_id = ?"), append(args, opts.withUserId)
	}

	var sessions []*Session
	err := r.list(ctx, &sessions, strings.Join(where, " and"), args, opt...)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return sessions, nil
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

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit.  Supports WithOrder option.
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, db.WithLimit(limit))
	if opts.withOrder != "" {
		dbOpts = append(dbOpts, db.WithOrder(opts.withOrder))
	}
	return r.reader.SearchWhere(ctx, resources, where, args, dbOpts...)
}

func fetchStates(ctx context.Context, r db.Reader, sessionId string, opt ...db.Option) ([]*State, error) {
	var states []*State
	if err := r.SearchWhere(ctx, &states, "session_id = ?", []interface{}{sessionId}, opt...); err != nil {
		return nil, fmt.Errorf("fetch session states: %w", err)
	}
	if len(states) == 0 {
		return nil, nil
	}
	return states, nil
}
