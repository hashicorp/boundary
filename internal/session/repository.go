package session

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
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

// CreateSession inserts into the repository and returns the new Session with
// its State of "Pending".  No options are currently supported.
func (r *Repository) CreateSession(ctx context.Context, newSession *Session, opt ...Option) (*Session, *State, error) {
	if newSession == nil {
		return nil, nil, fmt.Errorf("create session: missing session: %w", db.ErrInvalidParameter)
	}
	if newSession.Session == nil {
		return nil, nil, fmt.Errorf("create session: missing session store: %w", db.ErrInvalidParameter)
	}
	if newSession.PublicId != "" {
		return nil, nil, fmt.Errorf("create session: public id is not empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ServerId == "" {
		return nil, nil, fmt.Errorf("create session: server id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ServerType == "" {
		return nil, nil, fmt.Errorf("create session: server type is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.TargetId == "" {
		return nil, nil, fmt.Errorf("create session: target id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.HostId == "" {
		return nil, nil, fmt.Errorf("create session: user id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.UserId == "" {
		return nil, nil, fmt.Errorf("create session: user id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.SetId == "" {
		return nil, nil, fmt.Errorf("create session: set id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.AuthTokenId == "" {
		return nil, nil, fmt.Errorf("create session: auth token id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ScopeId == "" {
		return nil, nil, fmt.Errorf("create session: scope id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.Address == "" {
		return nil, nil, fmt.Errorf("create session: address is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.Port == "" {
		return nil, nil, fmt.Errorf("create session: port id is empty: %w", db.ErrInvalidParameter)
	}

	id, err := newId()
	if err != nil {
		return nil, nil, fmt.Errorf("create session: %w", err)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, newSession.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, fmt.Errorf("create session: unable to get oplog wrapper: %w", err)
	}

	var returnedSession *Session
	var returnedState *State
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			returnedSession = newSession.Clone().(*Session)
			returnedSession.PublicId = id
			metadata := returnedSession.oplog(oplog.OpType_OP_TYPE_CREATE)
			if err = w.Create(ctx, returnedSession, db.WithOplog(oplogWrapper, metadata)); err != nil {
				return err
			}
			var foundStates []*State
			// trigger will create new "Pending" state
			if foundStates, err = fetchStates(ctx, read, returnedSession.PublicId); err != nil {
				return err
			}
			if len(foundStates) != 1 {
				return fmt.Errorf("%d states found for new session %s", len(foundStates), returnedSession.PublicId)
			}
			returnedState = foundStates[0]
			if returnedState.Status != Pending.String() {
				return fmt.Errorf("new session %s state is not valid: %s", returnedSession.PublicId, returnedState.Status)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create session: %w", err)
	}
	return returnedSession, returnedState, err
}

// LookupSession will look up a session in the repository and return the session
// with its states.  If the session is not found, it will return nil, nil, nil.
// No options are currently supported.
func (r *Repository) LookupSession(ctx context.Context, sessionId string, opt ...Option) (*Session, []*State, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("lookup session: missing sessionId id: %w", db.ErrInvalidParameter)
	}
	session := allocSession()
	session.PublicId = sessionId
	var states []*State
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupById(ctx, &session); err != nil {
				return fmt.Errorf("lookup session: failed %w for %s", err, sessionId)
			}
			var err error
			if states, err = fetchStates(ctx, read, sessionId); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("lookup session: %w", err)
	}
	return &session, states, nil
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
