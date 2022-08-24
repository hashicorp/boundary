package session

import (
	"context"
	"sort"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

// Clonable provides a cloning interface
type Cloneable interface {
	Clone() interface{}
}

// Repository is the session database repository
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
	const op = "session.NewRepository"
	if r == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil kms")
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

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit.  Supports WithOrder option.
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	const op = "session.(Repository).list"
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, db.WithLimit(limit))
	switch opts.withOrderByCreateTime {
	case db.AscendingOrderBy:
		dbOpts = append(dbOpts, db.WithOrder("create_time asc"))
	case db.DescendingOrderBy:
		dbOpts = append(dbOpts, db.WithOrder("create_time"))
	}
	if err := r.reader.SearchWhere(ctx, resources, where, args, dbOpts...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *Repository) convertToSessions(ctx context.Context, sessionList []*sessionListView, opt ...Option) ([]*Session, error) {
	const op = "session.(Repository).convertToSessions"
	opts := getOpts(opt...)

	if len(sessionList) == 0 {
		return nil, nil
	}
	sessions := []*Session{}
	// deduplication map of states by end_time
	states := map[*timestamp.Timestamp]*State{}
	var prevSessionId string
	var workingSession *Session
	for _, sv := range sessionList {
		if sv.PublicId != prevSessionId {
			if prevSessionId != "" {
				for _, s := range states {
					workingSession.States = append(workingSession.States, s)
				}
				states = map[*timestamp.Timestamp]*State{}
				sort.Slice(workingSession.States, func(i, j int) bool {
					return workingSession.States[i].StartTime.GetTimestamp().AsTime().After(workingSession.States[j].StartTime.GetTimestamp().AsTime())
				})
				sessions = append(sessions, workingSession)
			}
			prevSessionId = sv.PublicId
			workingSession = &Session{
				PublicId:          sv.PublicId,
				UserId:            sv.UserId,
				HostId:            sv.HostId,
				TargetId:          sv.TargetId,
				HostSetId:         sv.HostSetId,
				AuthTokenId:       sv.AuthTokenId,
				ProjectId:         sv.ProjectId,
				Certificate:       sv.Certificate,
				ExpirationTime:    sv.ExpirationTime,
				CtTofuToken:       sv.CtTofuToken,
				TofuToken:         sv.TofuToken, // will always be nil since it's not stored in the database.
				TerminationReason: sv.TerminationReason,
				CreateTime:        sv.CreateTime,
				UpdateTime:        sv.UpdateTime,
				Version:           sv.Version,
				Endpoint:          sv.Endpoint,
				ConnectionLimit:   sv.ConnectionLimit,
				KeyId:             sv.KeyId,
			}
			if opts.withListingConvert {
				workingSession.CtTofuToken = nil // CtTofuToken should not returned in lists
				workingSession.TofuToken = nil   // TofuToken should not returned in lists
				workingSession.KeyId = ""        // KeyId should not be returned in lists
			} else {
				if len(workingSession.CtTofuToken) > 0 {
					databaseWrapper, err := r.kms.GetWrapper(ctx, workingSession.ProjectId, kms.KeyPurposeDatabase)
					if err != nil {
						return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
					}
					if err := workingSession.decrypt(ctx, databaseWrapper); err != nil {
						return nil, errors.Wrap(ctx, err, op, errors.WithMsg("cannot decrypt session value"))
					}
				} else {
					workingSession.CtTofuToken = nil
				}
			}
		}

		if _, ok := states[sv.EndTime]; !ok {
			states[sv.EndTime] = &State{
				SessionId:       sv.PublicId,
				Status:          Status(sv.Status),
				PreviousEndTime: sv.PreviousEndTime,
				StartTime:       sv.StartTime,
				EndTime:         sv.EndTime,
			}
		}

	}
	for _, s := range states {
		workingSession.States = append(workingSession.States, s)
	}
	sort.Slice(workingSession.States, func(i, j int) bool {
		return workingSession.States[i].StartTime.GetTimestamp().AsTime().After(workingSession.States[j].StartTime.GetTimestamp().AsTime())
	})
	sessions = append(sessions, workingSession)
	return sessions, nil
}
