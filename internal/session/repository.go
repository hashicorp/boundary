// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util"
)

// Clonable provides a cloning interface
type Cloneable interface {
	Clone() any
}

// Repository is the session database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
	permissions  *perms.UserPermissions
	randomReader io.Reader
}

// RepositoryFactory is a function that creates a Repository.
type RepositoryFactory func(opt ...Option) (*Repository, error)

// NewRepository creates a new session Repository. Supports the options:
//   - WithLimit, which sets a default limit on results returned by repo operations.
//   - WithPermissions
//   - WithRandomReader
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "session.NewRepository"
	if util.IsNil(r) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if util.IsNil(w) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}

	if opts.withPermissions != nil {
		for _, p := range opts.withPermissions.Permissions {
			if p.Resource != resource.Session {
				return nil, errors.New(ctx, errors.InvalidParameter, op, "permission for incorrect resource")
			}
		}
	}

	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.withLimit,
		permissions:  opts.withPermissions,
		randomReader: opts.withRandomReader,
	}, nil
}

func (r *Repository) listPermissionWhereClauses() ([]string, []any) {
	var where []string
	var args []any

	if r.permissions == nil {
		return where, args
	}

	inClauseCnt := 0
	for _, p := range r.permissions.Permissions {
		if p.Action != action.List {
			continue
		}

		inClauseCnt++

		var clauses []string
		clauses = append(clauses, fmt.Sprintf("project_id = @project_id_%d", inClauseCnt))
		args = append(args, sql.Named(fmt.Sprintf("project_id_%d", inClauseCnt), p.GrantScopeId))

		if len(p.ResourceIds) > 0 && !p.All {
			clauses = append(clauses, fmt.Sprintf("public_id = any(@public_id_%d)", inClauseCnt))
			args = append(args, sql.Named(fmt.Sprintf("public_id_%d", inClauseCnt), "{"+strings.Join(p.ResourceIds, ",")+"}"))
		}

		if p.OnlySelf {
			inClauseCnt++
			clauses = append(clauses, fmt.Sprintf("user_id = @user_id_%d", inClauseCnt))
			args = append(args, sql.Named(fmt.Sprintf("user_id_%d", inClauseCnt), r.permissions.UserId))
		}

		where = append(where, fmt.Sprintf("(%s)", strings.Join(clauses, " and ")))
	}
	return where, args
}

func (r *Repository) convertToSessions(ctx context.Context, sessionList []*sessionListView) ([]*Session, error) {
	const op = "session.(Repository).convertToSessions"

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
				PublicId:                sv.PublicId,
				UserId:                  sv.UserId,
				HostId:                  sv.HostId,
				HostSetId:               sv.HostSetId,
				TargetId:                sv.TargetId,
				AuthTokenId:             sv.AuthTokenId,
				ProjectId:               sv.ProjectId,
				Certificate:             sv.Certificate,
				ExpirationTime:          sv.ExpirationTime,
				TerminationReason:       sv.TerminationReason,
				CreateTime:              sv.CreateTime,
				UpdateTime:              sv.UpdateTime,
				Version:                 sv.Version,
				Endpoint:                sv.Endpoint,
				ConnectionLimit:         sv.ConnectionLimit,
				CtCertificatePrivateKey: nil, // CtCertificatePrivateKey should not be returned in lists
				CertificatePrivateKey:   nil, // CertificatePrivateKey should not be returned in lists
				CtTofuToken:             nil, // CtTofuToken should not be returned in lists
				TofuToken:               nil, // TofuToken should not be returned in lists
				KeyId:                   "",  // KeyId should not be returned in lists
			}
		}

		if _, ok := states[sv.EndTime]; !ok {
			states[sv.EndTime] = &State{
				SessionId: sv.PublicId,
				Status:    Status(sv.Status),
				StartTime: sv.StartTime,
				EndTime:   sv.EndTime,
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
