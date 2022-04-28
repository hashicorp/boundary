package sessions

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/sessions"
	"google.golang.org/grpc/codes"
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
	const op = "sessions.NewService"
	if repoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing session repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing iam repository")
	}
	return Service{repoFn: repoFn, iamRepoFn: iamRepoFn}, nil
}

var _ pbs.SessionServiceServer = Service{}

// GetSessions implements the interface pbs.SessionServiceServer.
func (s Service) GetSession(ctx context.Context, req *pbs.GetSessionRequest) (*pbs.GetSessionResponse, error) {
	const op = "sessions.(Service).GetSession"

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

	var outputFields perms.OutputFieldsMap
	authorizedActions := authResults.FetchActionSetForId(ctx, ses.GetPublicId(), IdActions)

	// Check to see if we need to verify Read vs. just ReadSelf
	if ses.UserId != authResults.UserId {
		if !authorizedActions.HasAction(action.Read) {
			return nil, handlers.ForbiddenError()
		}
		outputFields = authResults.FetchOutputFields(perms.Resource{
			Id:      ses.GetPublicId(),
			ScopeId: ses.ScopeId,
			Type:    resource.Session,
		}, action.Read).SelfOrDefaults(authResults.UserId)
	} else {
		var ok bool
		outputFields, ok = requests.OutputFields(ctx)
		if !ok {
			return nil, errors.New(ctx, errors.Internal, op, "no request context found")
		}
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions.Strings()))
	}

	item, err := toProto(ctx, ses, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetSessionResponse{Item: item}, nil
}

// ListSessions implements the interface pbs.SessionServiceServer.
func (s Service) ListSessions(ctx context.Context, req *pbs.ListSessionsRequest) (*pbs.ListSessionsResponse, error) {
	const op = "session.(Service).ListSessions"

	if err := validateListRequest(req); err != nil {
		return nil, err
	}

	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		// If it's forbidden, and it's a recursive request, and they're
		// successfully authenticated but just not authorized, keep going as we
		// may have authorization on downstream scopes. Or, if they've not
		// authenticated, still process in case u_anon has permissions.
		if (authResults.Error == handlers.ForbiddenError() || authResults.Error == handlers.UnauthenticatedError()) &&
			req.GetRecursive() &&
			authResults.AuthenticationFinished {
		} else {
			return nil, authResults.Error
		}
	}

	switch req.Style {
	case "":
		return s.listSessionsNormally(ctx, req, authResults)
	case "desktop-ui":
		return s.listSessionsDesktopUi(ctx, req, authResults)
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown style %s", req.Style))
	}
}

func (s Service) listSessionsNormally(ctx context.Context, req *pbs.ListSessionsRequest, authResults auth.VerifyResults) (*pbs.ListSessionsResponse, error) {
	const op = "session.(Service).listSessionsNormally"

	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	scopeResourceInfo, err := scopeids.GetListingResourceInformation(
		ctx,
		scopeids.GetListingResourceInformationInput{
			IamRepoFn:       s.iamRepoFn,
			AuthResults:     authResults,
			RootScopeId:     req.GetScopeId(),
			Type:            resource.Session,
			Recursive:       req.GetRecursive(),
			DirectOnly:      false,
			MinimalInfoRepo: repo,
			ActionSet:       IdActions,
		},
	)
	if err != nil {
		return nil, err
	}
	// If no scopes match or we match scopes but there are no resources in them
	// that we are authorized to see, return an empty response
	if len(scopeResourceInfo.ScopeIds) == 0 ||
		len(scopeResourceInfo.ResourceIds) == 0 {
		return &pbs.ListSessionsResponse{}, nil
	}

	sesList, err := s.listFromRepoViaSessionIds(ctx, scopeResourceInfo.ResourceIds)
	if err != nil {
		return nil, err
	}
	if len(sesList) == 0 {
		return &pbs.ListSessionsResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.Session, 0, len(sesList))
	res := perms.Resource{
		Type: resource.Session,
	}
	for _, item := range sesList {
		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(scopeResourceInfo.ScopeResourceMap[item.ScopeId].ScopeInfo))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(scopeResourceInfo.ScopeResourceMap[item.ScopeId].Resources[item.PublicId].AuthorizedActions.Strings()))
		}

		item, err := toProto(ctx, item, outputOpts...)
		if err != nil {
			return nil, err
		}

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}

	return &pbs.ListSessionsResponse{Items: finalItems}, nil
}

func (s Service) listSessionsDesktopUi(ctx context.Context, req *pbs.ListSessionsRequest, authResults auth.VerifyResults) (*pbs.ListSessionsResponse, error) {
	const op = "session.(Service).listSessionsDesktopUi"

	scopeIds, scopeInfoMap, err := scopeids.GetListingScopeIds(
		ctx,
		s.iamRepoFn,
		authResults,
		req.GetScopeId(),
		resource.Session,
		req.GetRecursive(),
		false,
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// If no scopes match, return an empty response
	if len(scopeInfoMap) == 0 {
		return &pbs.ListSessionsResponse{}, nil
	}

	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	scopedResourceIds, err := repo.FetchIdsWithOptions(ctx, session.WithScopeIds(scopeIds), session.WithUserId(authResults.UserId), session.WithNonTerminatedSessionsOnly(true))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	res := perms.Resource{
		Type: resource.Session,
	}

	resourceIdsToAuthActions := make(map[string]action.ActionSet)
	var allResourceIds []string
	for scopeId, minimalResourceInfos := range scopedResourceIds {
		for _, minimalResource := range minimalResourceInfos {
			res.Id = minimalResource.PublicId
			res.ScopeId = scopeId
			authorizedActions := authResults.FetchActionSetForId(ctx, minimalResource.PublicId, IdActions, auth.WithResource(&res))
			if len(authorizedActions) == 0 {
				continue
			}

			if authorizedActions.OnlySelf() && minimalResource.UserId != authResults.UserId {
				continue
			}

			resourceIdsToAuthActions[minimalResource.PublicId] = authorizedActions
			allResourceIds = append(allResourceIds, minimalResource.PublicId)
		}
	}

	sesList, err := s.listFromRepo(ctx, session.WithSessionIds(allResourceIds...))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(sesList) == 0 {
		return &pbs.ListSessionsResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	finalItems := make([]*pb.Session, 0, len(sesList))

	for _, item := range sesList {
		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[item.ScopeId]))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(resourceIdsToAuthActions[item.PublicId].Strings()))
		}

		item, err := toProto(ctx, item, outputOpts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}

	return &pbs.ListSessionsResponse{Items: finalItems}, nil
}

// CancelSession implements the interface pbs.SessionServiceServer.
func (s Service) CancelSession(ctx context.Context, req *pbs.CancelSessionRequest) (*pbs.CancelSessionResponse, error) {
	const op = "sessions.(Service).CancelSession"

	if err := validateCancelRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.CancelSelf)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	// We'll verify it's not already canceled, but after checking auth so as not
	// to leak that information.
	ses, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	var outputFields perms.OutputFieldsMap
	authorizedActions := authResults.FetchActionSetForId(ctx, ses.GetPublicId(), IdActions)

	// Check to see if we need to verify Cancel vs. just CancelSelf
	if ses.UserId != authResults.UserId {
		if !authorizedActions.HasAction(action.Cancel) {
			return nil, handlers.ForbiddenError()
		}
		outputFields = authResults.FetchOutputFields(perms.Resource{
			Id:      ses.GetPublicId(),
			ScopeId: ses.ScopeId,
			Type:    resource.Session,
		}, action.Cancel).SelfOrDefaults(authResults.UserId)
	} else {
		var ok bool
		outputFields, ok = requests.OutputFields(ctx)
		if !ok {
			return nil, errors.New(ctx, errors.Internal, op, "no request context found")
		}
	}

	var skipCancel bool
	for _, state := range ses.States {
		switch state.Status {
		case session.StatusCanceling, session.StatusTerminated:
			skipCancel = true
		}
	}

	if !skipCancel {
		ses, err = s.cancelInRepo(ctx, req.GetId(), req.GetVersion())
		if err != nil {
			return nil, err
		}
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions.Strings()))
	}

	item, err := toProto(ctx, ses, outputOpts...)
	if err != nil {
		return nil, err
	}
	return &pbs.CancelSessionResponse{Item: item}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*session.Session, error) {
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
	return sess, nil
}

func (s Service) listFromRepo(ctx context.Context, opt ...session.Option) ([]*session.Session, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	sesList, err := repo.ListSessions(ctx, opt...)
	if err != nil {
		return nil, err
	}
	return sesList, nil
}

func (s Service) listFromRepoViaScopeIds(ctx context.Context, scopeIds []string, opt ...session.Option) ([]*session.Session, error) {
	return s.listFromRepo(ctx, session.WithScopeIds(scopeIds))
}

func (s Service) listFromRepoViaSessionIds(ctx context.Context, sessionIds []string) ([]*session.Session, error) {
	return s.listFromRepo(ctx, session.WithSessionIds(sessionIds...))
}

func (s Service) cancelInRepo(ctx context.Context, id string, version uint32) (*session.Session, error) {
	const op = "sessions.(Service).cancelInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CancelSession(ctx, id, version)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update session"))
	}
	return out, nil
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

func toProto(ctx context.Context, in *session.Session, opt ...handlers.Option) (*pb.Session, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building auth token proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Session{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.ScopeId
	}
	if outputFields.Has(globals.TargetIdField) {
		out.TargetId = in.TargetId
	}
	if outputFields.Has(globals.TypeField) {
		out.Type = target.SubtypeFromId(in.TargetId).String()
	}
	if outputFields.Has(globals.CreatedTimeField) {
		out.CreatedTime = in.CreateTime.GetTimestamp()
	}
	if outputFields.Has(globals.UpdatedTimeField) {
		out.UpdatedTime = in.UpdateTime.GetTimestamp()
	}
	if outputFields.Has(globals.VersionField) {
		out.Version = in.Version
	}
	if outputFields.Has(globals.UserIdField) {
		out.UserId = in.UserId
	}
	if outputFields.Has(globals.HostIdField) {
		out.HostId = in.HostId
	}
	if outputFields.Has(globals.HostSetIdField) {
		out.HostSetId = in.HostSetId
	}
	if outputFields.Has(globals.AuthTokenIdField) {
		out.AuthTokenId = in.AuthTokenId
	}
	if outputFields.Has(globals.EndpointField) {
		out.Endpoint = in.Endpoint
	}
	if outputFields.Has(globals.HostIdField) {
		out.HostId = in.HostId
	}
	if outputFields.Has(globals.ExpirationTimeField) {
		out.ExpirationTime = in.ExpirationTime.GetTimestamp()
	}
	if outputFields.Has(globals.CertificateField) {
		out.Certificate = in.Certificate
	}
	if outputFields.Has(globals.TerminationReasonField) {
		out.TerminationReason = in.TerminationReason
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	// TODO: Provide the ServerType and the ServerId when that information becomes relevant in the API.
	if len(in.States) > 0 {
		if outputFields.Has(globals.StatusField) {
			out.Status = in.States[0].Status.String()
		}
		if outputFields.Has(globals.StatesField) {
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
		}
	}

	if len(in.Connections) > 0 {
		if outputFields.Has(globals.ConnectionsField) {
			connections := make([]*pb.Connection, 0, len(in.Connections))
			for _, c := range in.Connections {
				connections = append(connections, &pb.Connection{
					ClientTcpAddress:   c.ClientTcpAddress,
					ClientTcpPort:      c.ClientTcpPort,
					EndpointTcpAddress: c.EndpointTcpAddress,
					EndpointTcpPort:    c.EndpointTcpPort,
					BytesUp:            c.BytesUp,
					BytesDown:          c.BytesDown,
					ClosedReason:       c.ClosedReason,
				})
			}
			out.Connections = append(out.Connections, connections...)
		}
	}

	return &out, nil
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
