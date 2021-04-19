package sessions

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/sessions"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
)

var (
	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.ActionSet{
		action.NoOp,
		action.Read,
		action.ReadSelf,
		action.Cancel,
		action.CancelSelf,
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.List,
	}
)

// Service handles request as described by the pbs.SessionServiceServer interface.
type Service struct {
	pbs.UnimplementedSessionServiceServer

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
	authResults := s.authResult(ctx, req.GetId(), action.ReadSelf)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ses, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	authzdActions := authResults.FetchActionSetForId(ctx, ses.Id, IdActions)
	// Check to see if we need to verify Read vs. just ReadSelf
	if ses.GetUserId() != authResults.UserId {
		var found bool
		for _, v := range authzdActions {
			if v == action.Read {
				found = true
				break
			}
		}
		if !found {
			return nil, handlers.ForbiddenError()
		}
	}

	ses.Scope = authResults.Scope
	ses.AuthorizedActions = authzdActions.Strings()
	return &pbs.GetSessionResponse{Item: ses}, nil
}

// ListSessions implements the interface pbs.SessionServiceServer.
func (s Service) ListSessions(ctx context.Context, req *pbs.ListSessionsRequest) (*pbs.ListSessionsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}

	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		// If it's forbidden, and it's a recursive request, and they're
		// successfully authenticated but just not authorized, keep going as we
		// may have authorization on downstream scopes.
		if authResults.Error == handlers.ForbiddenError() &&
			req.GetRecursive() &&
			authResults.AuthenticationFinished {
		} else {
			return nil, authResults.Error
		}
	}

	scopeIds, scopeInfoMap, err := scopeids.GetListingScopeIds(ctx,
		s.iamRepoFn, authResults, req.GetScopeId(), resource.Session, req.GetRecursive(), false)
	if err != nil {
		return nil, err
	}
	// If no scopes match, return an empty response
	if len(scopeIds) == 0 {
		return &pbs.ListSessionsResponse{}, nil
	}

	seslist, err := s.listFromRepo(ctx, scopeIds, authResults.UserId == auth.AnonymousUserId)
	if err != nil {
		return nil, err
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.Session, 0, len(seslist))
	res := &perms.Resource{
		Type: resource.Session,
	}
	for _, item := range seslist {
		item.Scope = scopeInfoMap[item.GetScopeId()]
		res.ScopeId = item.Scope.Id
		authorizedActions := authResults.FetchActionSetForId(ctx, item.Id, IdActions, auth.WithResource(res))
		if len(authorizedActions) == 0 {
			continue
		}
		onlySelf := true
		for _, v := range authorizedActions {
			if v != action.ReadSelf && v != action.CancelSelf {
				onlySelf = false
				break
			}
		}
		if onlySelf && item.GetUserId() != authResults.UserId {
			continue
		}

		item.AuthorizedActions = authorizedActions.Strings()

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}

	return &pbs.ListSessionsResponse{Items: finalItems}, nil
}

// CancelSession implements the interface pbs.SessionServiceServer.
func (s Service) CancelSession(ctx context.Context, req *pbs.CancelSessionRequest) (*pbs.CancelSessionResponse, error) {
	if err := validateCancelRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.CancelSelf)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	ses, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	authzdActions := authResults.FetchActionSetForId(ctx, ses.Id, IdActions)
	// Check to see if we need to verify Read vs. just ReadSelf
	if ses.GetUserId() != authResults.UserId {
		var found bool
		for _, v := range authzdActions {
			if v == action.Cancel {
				found = true
				break
			}
		}
		if !found {
			return nil, handlers.ForbiddenError()
		}
	}

	ses, err = s.cancelInRepo(ctx, req.GetId(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	ses.Scope = authResults.Scope
	ses.AuthorizedActions = authzdActions.Strings()
	return &pbs.CancelSessionResponse{Item: ses}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Session, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	sess, _, err := repo.LookupSession(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, handlers.NotFoundErrorf("Session %q doesn't exist.", id)
		}
		return nil, err
	}
	if sess == nil {
		return nil, handlers.NotFoundErrorf("Session %q doesn't exist.", id)
	}
	return toProto(sess), nil
}

func (s Service) listFromRepo(ctx context.Context, scopeIds []string, anonUser bool) ([]*pb.Session, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	seslist, err := repo.ListSessions(ctx, session.WithScopeIds(scopeIds))
	if err != nil {
		return nil, err
	}
	var outSl []*pb.Session
	for _, ses := range seslist {
		outSl = append(outSl, toProto(ses, handlers.WithAnonymousListing(anonUser)))
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
	case action.Read, action.ReadSelf, action.Cancel, action.CancelSelf:
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
		res.Error = stderrors.New("unsupported action")
		return res
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toProto(in *session.Session, opt ...handlers.Option) *pb.Session {
	anonListing := handlers.GetOpts(opt...).WithAnonymousListing
	if anonListing {
		return &pb.Session{
			Id:       in.GetPublicId(),
			ScopeId:  in.ScopeId,
			TargetId: in.TargetId,
		}
	}
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

		CreatedTime:       in.CreateTime.GetTimestamp(),
		UpdatedTime:       in.UpdateTime.GetTimestamp(),
		ExpirationTime:    in.ExpirationTime.GetTimestamp(),
		Certificate:       in.Certificate,
		TerminationReason: in.TerminationReason,
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
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, session.SessionPrefix)
}

func validateListRequest(req *pbs.ListSessionsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		!req.GetRecursive() {
		badFields["scope_id"] = "This field must be a valid project scope ID or the list operation must be recursive."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateCancelRequest(req *pbs.CancelSessionRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), session.SessionPrefix) {
		badFields["id"] = "Improperly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
