// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
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
	IdActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.ReadSelf,
		action.Cancel,
		action.CancelSelf,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.List,
	)
)

func init() {
	// TODO: refactor to remove IdActions and CollectionActions package variables
	action.RegisterResource(resource.Session, IdActions, CollectionActions)
}

// Service handles request as described by the pbs.SessionServiceServer interface.
type Service struct {
	pbs.UnsafeSessionServiceServer

	repoFn      session.RepositoryFactory
	iamRepoFn   common.IamRepoFactory
	maxPageSize uint
}

var _ pbs.SessionServiceServer = (*Service)(nil)

// NewService returns a session service which handles session related requests to boundary.
func NewService(ctx context.Context, repoFn session.RepositoryFactory, iamRepoFn common.IamRepoFactory, maxPageSize uint) (Service, error) {
	const op = "sessions.NewService"
	if repoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing session repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{repoFn: repoFn, iamRepoFn: iamRepoFn, maxPageSize: maxPageSize}, nil
}

// GetSessions implements the interface pbs.SessionServiceServer.
func (s Service) GetSession(ctx context.Context, req *pbs.GetSessionRequest) (*pbs.GetSessionResponse, error) {
	const op = "sessions.(Service).GetSession"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.ReadSelf, false, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ses, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	var outputFields *perms.OutputFields
	authorizedActions := authResults.FetchActionSetForId(ctx, ses.GetPublicId(), IdActions)

	// Check to see if we need to verify Read vs. just ReadSelf
	if ses.UserId != authResults.UserId {
		if !authorizedActions.HasAction(action.Read) {
			return nil, handlers.ForbiddenError()
		}
		outputFields = authResults.FetchOutputFields(perms.Resource{
			Id:            ses.GetPublicId(),
			ScopeId:       ses.ProjectId,
			Type:          resource.Session,
			ParentScopeId: authResults.Scope.ParentScopeId,
		}, action.Read).SelfOrDefaults(authResults.UserId)
	} else {
		var ok bool
		outputFields, ok = requests.OutputFields(ctx)
		if !ok {
			return nil, errors.New(ctx, errors.Internal, op, "no request context found")
		}
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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

	if err := validateListRequest(ctx, req); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	authResults := s.authResult(ctx, req.GetScopeId(), action.List, false, req.GetRecursive())
	if authResults.Error != nil {
		// If it's forbidden, and it's a recursive request, and they're
		// successfully authenticated but just not authorized, keep going as we
		// may have authorization on downstream scopes. Or, if they've not
		// authenticated, still process in case u_anon has permissions.
		if (authResults.Error == handlers.ForbiddenError() || authResults.Error == handlers.UnauthenticatedError()) &&
			req.GetRecursive() &&
			authResults.AuthenticationFinished {
		} else {
			return nil, errors.Wrap(ctx, authResults.Error, op)
		}
	}

	var scopeIds map[string]*scopes.ScopeInfo
	var err error
	if !req.GetRecursive() {
		scopeIds = map[string]*scopes.ScopeInfo{authResults.Scope.Id: authResults.Scope}
	} else {
		scopeIds, err = authResults.ScopesAuthorizedForList(ctx, req.GetScopeId(), resource.Session)
		if err != nil {
			return nil, err
		}
	}

	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}
	var filterItemFn func(ctx context.Context, item *session.Session) (bool, error)
	switch {
	case req.GetFilter() != "":
		// Only use a filter if we need to
		filter, err := handlers.NewFilter(ctx, req.GetFilter())
		if err != nil {
			return nil, err
		}
		filterItemFn = func(ctx context.Context, item *session.Session) (bool, error) {
			outputOpts, ok := newOutputOpts(ctx, item, scopeIds, authResults)
			if !ok {
				return false, nil
			}
			pbItem, err := toProto(ctx, item, outputOpts...)
			if err != nil {
				return false, err
			}
			return filter.Match(pbItem), nil
		}
	default:
		filterItemFn = func(ctx context.Context, item *session.Session) (bool, error) {
			return true, nil
		}
	}

	grantsHash, err := authResults.GrantsHash(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	listPerms := authResults.ACL().ListPermissions(scopeIds, resource.Session, IdActions, authResults.UserId)

	repo, err := s.repoFn(session.WithPermissions(&perms.UserPermissions{
		UserId:      authResults.UserId,
		Permissions: listPerms,
	}))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var listResp *pagination.ListResponse[*session.Session]
	var sortBy string
	includeTerminated := req.GetIncludeTerminated()
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, err = session.List(ctx, grantsHash, pageSize, filterItemFn, repo, includeTerminated)
		if err != nil {
			return nil, err
		}
	} else {
		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.Session, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, err = session.ListPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, includeTerminated)
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, err = session.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, includeTerminated)
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, err = session.ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, includeTerminated)
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*pb.Session, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok := newOutputOpts(ctx, item, scopeIds, authResults)
		if !ok {
			continue
		}
		item, err := toProto(ctx, item, outputOpts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		finalItems = append(finalItems, item)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListSessionsResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}

	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_SESSION)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// CancelSession implements the interface pbs.SessionServiceServer.
func (s Service) CancelSession(ctx context.Context, req *pbs.CancelSessionRequest) (*pbs.CancelSessionResponse, error) {
	const op = "sessions.(Service).CancelSession"

	if err := validateCancelRequest(req); err != nil {
		return nil, err
	}
	// Ignore decryption failures to ensure the user can always cancel a session.
	authResults := s.authResult(ctx, req.GetId(), action.CancelSelf, true, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	// We'll verify it's not already canceled, but after checking auth so as not
	// to leak that information.
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	// Ignore decryption failures to ensure the user can always cancel a session.
	ses, _, err := repo.LookupSession(ctx, req.GetId(), session.WithIgnoreDecryptionFailures(true))
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, handlers.NotFoundErrorf("Session %q doesn't exist.", req.GetId())
		}
		return nil, err
	}
	if ses == nil {
		return nil, handlers.NotFoundErrorf("Session %q doesn't exist.", req.GetId())
	}

	var outputFields *perms.OutputFields
	authorizedActions := authResults.FetchActionSetForId(ctx, ses.GetPublicId(), IdActions)

	// Check to see if we need to verify Cancel vs. just CancelSelf
	if ses.UserId != authResults.UserId {
		if !authorizedActions.HasAction(action.Cancel) {
			return nil, handlers.ForbiddenError()
		}
		outputFields = authResults.FetchOutputFields(perms.Resource{
			Id:            ses.GetPublicId(),
			ScopeId:       ses.ProjectId,
			Type:          resource.Session,
			ParentScopeId: authResults.Scope.ParentScopeId,
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
		// Ignore decryption failures to ensure the user can always cancel a session.
		ses, err = repo.CancelSession(ctx, req.GetId(), req.GetVersion(), session.WithIgnoreDecryptionFailures(true))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update session"))
		}
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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

func (s Service) authResult(ctx context.Context, id string, a action.Type, ignoreSessionDecryptionFailure, isRecursive bool) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	opts := []auth.Option{auth.WithAction(a), auth.WithRecursive(isRecursive)}
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
		t, _, err := repo.LookupSession(ctx, id, session.WithIgnoreDecryptionFailures(ignoreSessionDecryptionFailure))
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
	return auth.Verify(ctx, resource.Session, opts...)
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
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.SessionPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListSessionsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		!req.GetRecursive() {
		badFields["scope_id"] = "This field must be a valid project scope ID or the list operation must be recursive."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateCancelRequest(req *pbs.CancelSessionRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.SessionPrefix) {
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

func newOutputOpts(ctx context.Context, item *session.Session, scopeIds map[string]*scopes.ScopeInfo, authResults auth.VerifyResults) ([]handlers.Option, bool) {
	res := perms.Resource{
		Type:          resource.Session,
		Id:            item.GetPublicId(),
		ScopeId:       item.GetProjectId(),
		ParentScopeId: scopeIds[item.ProjectId].ParentScopeId,
	}
	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
	if len(authorizedActions) == 0 {
		return nil, false
	}

	outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(scopeIds[item.ProjectId]))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
	}
	return outputOpts, true
}
