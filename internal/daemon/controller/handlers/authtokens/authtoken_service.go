// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtokens

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"google.golang.org/grpc/codes"
)

var (
	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.ReadSelf,
		action.Delete,
		action.DeleteSelf,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.List,
	)
)

func init() {
	// TODO: refactor to remove IdActionsMap and CollectionActions package variables
	action.RegisterResource(resource.AuthToken, IdActions, CollectionActions)
}

// Service handles request as described by the pbs.AuthTokenServiceServer interface.
type Service struct {
	pbs.UnsafeAuthTokenServiceServer

	repoFn      common.AuthTokenRepoFactory
	iamRepoFn   common.IamRepoFactory
	maxPageSize uint
}

var _ pbs.AuthTokenServiceServer = (*Service)(nil)

// NewService returns a user service which handles user related requests to boundary.
func NewService(ctx context.Context, repo common.AuthTokenRepoFactory, iamRepoFn common.IamRepoFactory, maxPageSize uint) (Service, error) {
	const op = "authtoken.NewService"
	if repo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing auth token repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{repoFn: repo, iamRepoFn: iamRepoFn, maxPageSize: maxPageSize}, nil
}

// ListAuthTokens implements the interface pbs.AuthTokenServiceServer.
func (s Service) ListAuthTokens(ctx context.Context, req *pbs.ListAuthTokensRequest) (*pbs.ListAuthTokensResponse, error) {
	const op = "authtokens.(Service).ListAuthTokens"

	if err := validateListRequest(ctx, req); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	authResults := s.authResult(ctx, req.GetScopeId(), action.List, req.GetRecursive())
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

	scopeIds, scopeInfoMap, err := scopeids.GetListingScopeIds(
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.AuthToken, req.GetRecursive())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}

	var filterItemFn func(ctx context.Context, item *authtoken.AuthToken) (bool, error)
	switch {
	case req.GetFilter() != "":
		// Only use a filter if we need to
		filter, err := handlers.NewFilter(ctx, req.GetFilter())
		if err != nil {
			return nil, err
		}
		filterItemFn = func(ctx context.Context, item *authtoken.AuthToken) (bool, error) {
			outputOpts, ok := newOutputOpts(ctx, item, scopeInfoMap, authResults)
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
		filterItemFn = func(ctx context.Context, item *authtoken.AuthToken) (bool, error) {
			return true, nil
		}
	}

	grantsHash, err := authResults.GrantsHash(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var listResp *pagination.ListResponse[*authtoken.AuthToken]
	var sortBy string
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, err = authtoken.List(ctx, grantsHash, pageSize, filterItemFn, repo, scopeIds)
		if err != nil {
			return nil, err
		}
	} else {
		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.AuthToken, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, err = authtoken.ListPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, err = authtoken.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, err = authtoken.ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*pb.AuthToken, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok := newOutputOpts(ctx, item, scopeInfoMap, authResults)
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
	resp := &pbs.ListAuthTokensResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}

	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_AUTH_TOKEN)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// GetAuthToken implements the interface pbs.AuthTokenServiceServer.
func (s Service) GetAuthToken(ctx context.Context, req *pbs.GetAuthTokenRequest) (*pbs.GetAuthTokenResponse, error) {
	const op = "authtokens.(Service).GetAuthToken"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.ReadSelf, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	at, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	var outputFields *perms.OutputFields
	authorizedActions := authResults.FetchActionSetForId(ctx, at.GetPublicId(), IdActions)

	// Check to see if we need to verify Read vs. just ReadSelf
	if at.GetIamUserId() != authResults.UserId {
		if !authorizedActions.HasAction(action.Read) {
			return nil, handlers.ForbiddenError()
		}
		outputFields = authResults.FetchOutputFields(perms.Resource{
			Id:      at.GetPublicId(),
			ScopeId: at.GetScopeId(),
			Type:    resource.AuthToken,
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

	item, err := toProto(ctx, at, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetAuthTokenResponse{Item: item}, nil
}

// DeleteAuthToken implements the interface pbs.AuthTokenServiceServer.
func (s Service) DeleteAuthToken(ctx context.Context, req *pbs.DeleteAuthTokenRequest) (*pbs.DeleteAuthTokenResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.DeleteSelf, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	at, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	authorizedActions := authResults.FetchActionSetForId(ctx, at.GetPublicId(), IdActions)

	// Check to see if we need to verify Delete vs. just DeleteSelf
	if at.GetIamUserId() != authResults.UserId {
		if !authorizedActions.HasAction(action.Delete) {
			return nil, handlers.ForbiddenError()
		}
	}

	_, err = s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*authtoken.AuthToken, error) {
	const op = "authtokens.(Service).getFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	at, err := repo.LookupAuthToken(ctx, id)
	if err != nil && !errors.IsNotFoundError(err) {
		return nil, errors.Wrap(ctx, err, op)
	}
	if at == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("AuthToken %q not found", id))
	}
	return at, nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "authtokens.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}
	rows, err := repo.DeleteAuthToken(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete user"))
	}
	return rows > 0, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type, isRecursive bool) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	opts := []auth.Option{auth.WithAction(a), auth.WithRecursive(isRecursive)}
	switch a {
	case action.List, action.Create:
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
	default:
		repo, err := s.repoFn()
		if err != nil {
			res.Error = err
			return res
		}
		authTok, err := repo.LookupAuthToken(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if authTok == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = authTok.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, resource.AuthToken, opts...)
}

func toProto(ctx context.Context, in *authtoken.AuthToken, opt ...handlers.Option) (*pb.AuthToken, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building auth token proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.AuthToken{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetScopeId()
	}
	if outputFields.Has(globals.UserIdField) {
		out.UserId = in.GetIamUserId()
	}
	if outputFields.Has(globals.AuthMethodIdField) {
		out.AuthMethodId = in.GetAuthMethodId()
	}
	if outputFields.Has(globals.AccountIdField) {
		out.AccountId = in.GetAuthAccountId()
	}
	if outputFields.Has(globals.CreatedTimeField) {
		out.CreatedTime = in.GetCreateTime().GetTimestamp()
	}
	if outputFields.Has(globals.UpdatedTimeField) {
		out.UpdatedTime = in.GetUpdateTime().GetTimestamp()
	}
	if outputFields.Has(globals.ApproximateLastUsedTimeField) {
		out.ApproximateLastUsedTime = in.GetApproximateLastAccessTime().GetTimestamp()
	}
	if outputFields.Has(globals.ExpirationTimeField) {
		out.ExpirationTime = in.GetExpirationTime().GetTimestamp()
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}

	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetAuthTokenRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.AuthTokenPrefix)
}

func validateDeleteRequest(req *pbs.DeleteAuthTokenRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, globals.AuthTokenPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListAuthTokensRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "This field must be 'global' or a valid org scope id."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func newOutputOpts(ctx context.Context, item *authtoken.AuthToken, scopeInfoMap map[string]*scopes.ScopeInfo, authResults auth.VerifyResults) ([]handlers.Option, bool) {
	res := perms.Resource{
		Type: resource.AuthToken,
	}
	res.Id = item.GetPublicId()
	res.ScopeId = item.GetScopeId()
	res.ParentScopeId = scopeInfoMap[item.GetScopeId()].GetParentScopeId()

	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res))
	if len(authorizedActions) == 0 {
		return nil, false
	}

	if authorizedActions.OnlySelf() && item.GetIamUserId() != authResults.UserId {
		return nil, false
	}

	outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[item.GetScopeId()]))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions.Strings()))
	}
	return outputOpts, true
}
