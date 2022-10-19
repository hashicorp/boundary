package sessions

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
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
	pbs.UnsafeSessionServiceServer

	repoFn    session.RepositoryFactory
	iamRepoFn common.IamRepoFactory
}

var _ pbs.SessionServiceServer = (*Service)(nil)

// NewService returns a session service which handles session related requests to boundary.
func NewService(repoFn session.RepositoryFactory, iamRepoFn common.IamRepoFactory) (Service, error) {
	const op = "sessions.NewService"
	if repoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing session repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing iam repository")
	}
	return Service{repoFn: repoFn, iamRepoFn: iamRepoFn}, nil
}

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
	if ses.UserId != authResults.UserData.User.Id {
		if !authorizedActions.HasAction(action.Read) {
			return nil, handlers.ForbiddenError()
		}
		outputFields = authResults.FetchOutputFields(perms.Resource{
			Id:      ses.GetPublicId(),
			ScopeId: ses.ProjectId,
			Type:    resource.Session,
		}, action.Read).SelfOrDefaults(authResults.UserData.User.Id)
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

	var scopeIds map[string]*scopes.ScopeInfo
	var err error

	if !req.GetRecursive() {
		scopeIds = map[string]*scopes.ScopeInfo{authResults.Scope.Id: authResults.Scope}
	} else {
		scopeIds, err = authResults.ScopesAuthorizedForList(ctx, req.GetScopeId(), resource.Session)
	}

	listPerms := authResults.ACL().ListPermissions(scopeIds, resource.Session, IdActions)

	repo, err := s.repoFn(session.WithPermissions(&perms.UserPermissions{
		UserId:      authResults.UserData.User.Id,
		Permissions: listPerms,
	}))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	sesList, err := repo.ListSessions(ctx, session.WithTerminated(req.GetIncludeTerminated()))
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
		res.Id = item.GetPublicId()
		res.ScopeId = item.GetProjectId()
		authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
		if len(authorizedActions) == 0 {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserData.User.Id)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(scopeIds[item.ProjectId]))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
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
	if ses.UserId != authResults.UserData.User.Id {
		if !authorizedActions.HasAction(action.Cancel) {
			return nil, handlers.ForbiddenError()
		}
		outputFields = authResults.FetchOutputFields(perms.Resource{
			Id:      ses.GetPublicId(),
			ScopeId: ses.ProjectId,
			Type:    resource.Session,
		}, action.Cancel).SelfOrDefaults(authResults.UserData.User.Id)
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
		parentId = t.ProjectId
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
		out.ScopeId = in.ProjectId
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
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
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
