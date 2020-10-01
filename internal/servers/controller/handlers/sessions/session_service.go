package sessions

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/sessions"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// Service handles request as described by the pbs.SessionServiceServer interface.
type Service struct {
	repoFn    common.SessionRepoFactory
	iamRepoFn common.IamRepoFactory
}

// NewService returns a session service which handles session related requests to boundary.
func NewService(repoFn common.SessionRepoFactory, iamRepoFn common.IamRepoFactory) (Service, error) {
	if repoFn == nil {
		return Service{}, fmt.Errorf("nil session repository provided")
	}
	if iamRepoFn == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repoFn, iamRepoFn: iamRepoFn}, nil
}

var _ pbs.SessionServiceServer = Service{}

// GetSessions implements the interface pbs.SessionServiceServer.
func (s Service) GetSession(ctx context.Context, req *pbs.GetSessionRequest) (*pbs.GetSessionResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ses, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	ses.Scope = authResults.Scope
	return &pbs.GetSessionResponse{Item: ses}, nil
}

// ListSessions implements the interface pbs.SessionServiceServer.
func (s Service) ListSessions(ctx context.Context, req *pbs.ListSessionsRequest) (*pbs.ListSessionsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	seslist, err := s.listFromRepo(ctx, authResults.Scope.GetId())
	if err != nil {
		return nil, err
	}
	for _, item := range seslist {
		item.Scope = authResults.Scope
	}
	return &pbs.ListSessionsResponse{Items: seslist}, nil
}

// CancelSession implements the interface pbs.SessionServiceServer.
func (s Service) CancelSession(ctx context.Context, req *pbs.CancelSessionRequest) (*pbs.CancelSessionResponse, error) {
	if err := validateCancelRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Cancel)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ses, err := s.cancelInRepo(ctx, req.GetId(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	ses.Scope = authResults.Scope
	return &pbs.CancelSessionResponse{Item: ses}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Session, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	sess, _, err := repo.LookupSession(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("Session %q doesn't exist.", id)
		}
		return nil, err
	}
	if sess == nil {
		return nil, handlers.NotFoundErrorf("Session %q doesn't exist.", id)
	}
	return toProto(sess), nil
}

func (s Service) listFromRepo(ctx context.Context, scopeId string) ([]*pb.Session, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	seslist, err := repo.ListSessions(ctx, session.WithScopeId(scopeId))
	if err != nil {
		return nil, err
	}
	var outSl []*pb.Session
	for _, ses := range seslist {
		outSl = append(outSl, toProto(ses))
	}
	return outSl, nil
}

func (s Service) cancelInRepo(ctx context.Context, id string, version uint32) (*pb.Session, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CancelSession(ctx, id, version)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %w", err)
	}
	return toProto(out), nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.Session), auth.WithAction(a)}
	switch a {
	case action.List:
		parentId = id
		iamRepo, err := s.iamRepoFn()
		if err != nil {
			res.Error = err
			return res
		}
		scp, err := iamRepo.LookupScope(ctx, parentId)
		if err != nil {
			res.Error = err
			return res
		}
		if scp == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
	case action.Read, action.Cancel:
		repo, err := s.repoFn()
		if err != nil {
			res.Error = err
			return res
		}
		t, _, err := repo.LookupSession(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if t == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = t.ScopeId
		opts = append(opts, auth.WithId(id))
	default:
		res.Error = errors.New("unsupported action")
		return res
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toProto(in *session.Session) *pb.Session {
	out := pb.Session{
		Id:          in.GetPublicId(),
		ScopeId:     in.ScopeId,
		TargetId:    in.TargetId,
		Version:     in.Version,
		UserId:      in.UserId,
		HostId:      in.HostId,
		HostSetId:   in.HostSetId,
		AuthTokenId: in.AuthTokenId,
		Endpoint:    in.Endpoint,
		Type:        target.SubtypeFromId(in.TargetId).String(),
		// TODO: Provide the ServerType and the ServerId when that information becomes relevant in the API.

		CreatedTime:    in.CreateTime.GetTimestamp(),
		UpdatedTime:    in.UpdateTime.GetTimestamp(),
		ExpirationTime: in.ExpirationTime.GetTimestamp(),
		Certificate:    in.Certificate,
	}
	if len(in.States) > 0 {
		out.Status = in.States[0].Status.String()
	}
	for _, s := range in.States {
		sessState := &pb.SessionState{
			Status: s.Status.String(),
		}
		if s.StartTime != nil {
			sessState.StartTime = s.StartTime.GetTimestamp()
		}
		if s.EndTime != nil {
			sessState.EndTime = s.EndTime.GetTimestamp()
		}
		out.States = append(out.States, sessState)
	}
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetSessionRequest) error {
	return handlers.ValidateGetRequest(session.SessionPrefix, req, handlers.NoopValidatorFn)
}

func validateListRequest(req *pbs.ListSessionsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(scope.Project.Prefix(), req.GetScopeId()) {
		badFields["scope_id"] = "This field is required to have a properly formatted project scope id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateCancelRequest(req *pbs.CancelSessionRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(session.SessionPrefix, req.GetId()) {
		badFields["id"] = "Impropperly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
