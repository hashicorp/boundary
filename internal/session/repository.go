package session

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/hashicorp/boundary/internal/db"
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

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit.  Supports WithOrder option.
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opts options) error {
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

func (r *Repository) convertToSessions(ctx context.Context, sessionsWithState []*sessionView, opt ...Option) ([]*Session, error) {
	opts := getOpts(opt...)

	if len(sessionsWithState) == 0 {
		return nil, nil
	}
	sessions := []*Session{}
	var prevSessionId string
	var workingSession *Session
	for _, sv := range sessionsWithState {
		if sv.PublicId != prevSessionId {
			if prevSessionId != "" {
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
				ServerId:          sv.ServerId,
				ServerType:        sv.ServerType,
				TargetId:          sv.TargetId,
				HostSetId:         sv.HostSetId,
				AuthTokenId:       sv.AuthTokenId,
				ScopeId:           sv.ScopeId,
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
				KeyId:             sv.KeyId}
			if opts.withListingConvert {
				workingSession.CtTofuToken = nil // CtTofuToken should not returned in lists
				workingSession.TofuToken = nil   // TofuToken should not returned in lists
				workingSession.KeyId = ""        // KeyId should not be returned in lists
			} else {
				if len(workingSession.CtTofuToken) > 0 {
					databaseWrapper, err := r.kms.GetWrapper(ctx, workingSession.ScopeId, kms.KeyPurposeDatabase, kms.WithKeyId(workingSession.KeyId))
					if err != nil {
						return nil, fmt.Errorf("convert session: unable to get database wrapper: %w", err)
					}
					if err := workingSession.decrypt(ctx, databaseWrapper); err != nil {
						return nil, fmt.Errorf("convert session: cannot decrypt session value: %w", err)
					}
				} else {
					workingSession.CtTofuToken = nil
				}
			}
		}

		state := &State{
			SessionId:       sv.PublicId,
			Status:          Status(sv.Status),
			PreviousEndTime: sv.PreviousEndTime,
			StartTime:       sv.StartTime,
			EndTime:         sv.EndTime,
		}
		workingSession.States = append(workingSession.States, state)
	}
	sort.Slice(workingSession.States, func(i, j int) bool {
		return workingSession.States[i].StartTime.GetTimestamp().AsTime().After(workingSession.States[j].StartTime.GetTimestamp().AsTime())
	})
	sessions = append(sessions, workingSession)
	return sessions, nil
}
