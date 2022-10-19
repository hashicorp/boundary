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
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"google.golang.org/grpc/codes"
)

var (
	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.ActionSet{
		action.NoOp,
		action.Read,
		action.ReadSelf,
		action.Delete,
		action.DeleteSelf,
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.List,
	}
)

// Service handles request as described by the pbs.AuthTokenServiceServer interface.
type Service struct {
	pbs.UnsafeAuthTokenServiceServer

	repoFn    common.AuthTokenRepoFactory
	iamRepoFn common.IamRepoFactory
}

var _ pbs.AuthTokenServiceServer = (*Service)(nil)

// NewService returns a user service which handles user related requests to boundary.
func NewService(repo common.AuthTokenRepoFactory, iamRepoFn common.IamRepoFactory) (Service, error) {
	const op = "authtoken.NewService"
	if repo == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing auth token repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing iam repository")
	}
	return Service{repoFn: repo, iamRepoFn: iamRepoFn}, nil
}

// ListAuthTokens implements the interface pbs.AuthTokenServiceServer.
func (s Service) ListAuthTokens(ctx context.Context, req *pbs.ListAuthTokensRequest) (*pbs.ListAuthTokensResponse, error) {
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

	scopeIds, scopeInfoMap, err := scopeids.GetListingScopeIds(
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.AuthToken, req.GetRecursive())
	if err != nil {
		return nil, err
	}
	// If no scopes match, return an empty response
	if len(scopeIds) == 0 {
		return &pbs.ListAuthTokensResponse{}, nil
	}

	ul, err := s.listFromRepo(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	if len(ul) == 0 {
		return &pbs.ListAuthTokensResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.AuthToken, 0, len(ul))
	res := perms.Resource{
		Type: resource.AuthToken,
	}
	for _, at := range ul {
		res.Id = at.GetPublicId()
		res.ScopeId = at.GetScopeId()
		authorizedActions := authResults.FetchActionSetForId(ctx, at.GetPublicId(), IdActions, auth.WithResource(&res))
		if len(authorizedActions) == 0 {
			continue
		}

		if authorizedActions.OnlySelf() && at.GetIamUserId() != authResults.UserData.User.Id {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserData.User.Id)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[at.GetScopeId()]))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions.Strings()))
		}

		item, err := toProto(ctx, at, outputOpts...)
		if err != nil {
			return nil, err
		}

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}

	return &pbs.ListAuthTokensResponse{Items: finalItems}, nil
}

// GetAuthToken implements the interface pbs.AuthTokenServiceServer.
func (s Service) GetAuthToken(ctx context.Context, req *pbs.GetAuthTokenRequest) (*pbs.GetAuthTokenResponse, error) {
	const op = "authtokens.(Service).GetAuthToken"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.ReadSelf)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	at, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	var outputFields perms.OutputFieldsMap
	authorizedActions := authResults.FetchActionSetForId(ctx, at.GetPublicId(), IdActions)

	// Check to see if we need to verify Read vs. just ReadSelf
	if at.GetIamUserId() != authResults.UserData.User.Id {
		if !authorizedActions.HasAction(action.Read) {
			return nil, handlers.ForbiddenError()
		}
		outputFields = authResults.FetchOutputFields(perms.Resource{
			Id:      at.GetPublicId(),
			ScopeId: at.GetScopeId(),
			Type:    resource.AuthToken,
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
	authResults := s.authResult(ctx, req.GetId(), action.DeleteSelf)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	at, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	authorizedActions := authResults.FetchActionSetForId(ctx, at.GetPublicId(), IdActions)

	// Check to see if we need to verify Delete vs. just DeleteSelf
	if at.GetIamUserId() != authResults.UserData.User.Id {
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

func (s Service) listFromRepo(ctx context.Context, scopeIds []string) ([]*authtoken.AuthToken, error) {
	repo, err := s.repoFn()
	_ = repo
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListAuthTokens(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	return ul, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.AuthToken), auth.WithAction(a)}
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
	return auth.Verify(ctx, opts...)
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
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, authtoken.AuthTokenPrefix)
}

func validateDeleteRequest(req *pbs.DeleteAuthTokenRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, authtoken.AuthTokenPrefix)
}

func validateListRequest(req *pbs.ListAuthTokensRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "This field must be 'global' or a valid org scope id."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
