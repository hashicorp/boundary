package authtokens

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
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
	pbs.UnimplementedAuthTokenServiceServer

	repoFn    common.AuthTokenRepoFactory
	iamRepoFn common.IamRepoFactory
}

// NewService returns a user service which handles user related requests to boundary.
func NewService(repo common.AuthTokenRepoFactory, iamRepoFn common.IamRepoFactory) (Service, error) {
	const op = "authtoken.NewService"
	if repo == nil {
		return Service{}, errors.New(errors.InvalidParameter, op, "missing auth token repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.New(errors.InvalidParameter, op, "missing iam repository")
	}
	return Service{repoFn: repo, iamRepoFn: iamRepoFn}, nil
}

var _ pbs.AuthTokenServiceServer = Service{}

// ListAuthTokens implements the interface pbs.AuthTokenServiceServer.
func (s Service) ListAuthTokens(ctx context.Context, req *pbs.ListAuthTokensRequest) (*pbs.ListAuthTokensResponse, error) {
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

	scopeIds, scopeInfoMap, err := scopeids.GetListingScopeIds(
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.AuthToken, req.GetRecursive(), false)
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
	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.AuthToken, 0, len(ul))
	res := &perms.Resource{
		Type: resource.AuthToken,
	}
	for _, item := range ul {
		item.Scope = scopeInfoMap[item.GetScopeId()]
		res.ScopeId = item.Scope.Id
		authorizedActions := authResults.FetchActionSetForId(ctx, item.Id, IdActions, auth.WithResource(res))
		if len(authorizedActions) == 0 {
			continue
		}

		if authorizedActions.OnlySelf() && item.GetUserId() != authResults.UserId {
			continue
		}

		item.AuthorizedActions = authorizedActions.Strings()

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListAuthTokensResponse{Items: finalItems}, nil
}

// GetAuthToken implements the interface pbs.AuthTokenServiceServer.
func (s Service) GetAuthToken(ctx context.Context, req *pbs.GetAuthTokenRequest) (*pbs.GetAuthTokenResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.ReadSelf)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	authzdActions := authResults.FetchActionSetForId(ctx, u.Id, IdActions)
	// Check to see if we need to verify Read vs. just ReadSelf
	if u.GetUserId() != authResults.UserId {
		if !authzdActions.HasAction(action.Read) {
			return nil, handlers.ForbiddenError()
		}
	}

	u.Scope = authResults.Scope
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions).Strings()
	return &pbs.GetAuthTokenResponse{Item: u}, nil
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
	authzdActions := authResults.FetchActionSetForId(ctx, at.Id, IdActions)
	// Check to see if we need to verify Delete vs. just DeleteSelf
	if at.GetUserId() != authResults.UserId {
		if !authzdActions.HasAction(action.Delete) {
			return nil, handlers.ForbiddenError()
		}
	}

	_, err = s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.AuthToken, error) {
	const op = "authtokens.(Service).getFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	u, err := repo.LookupAuthToken(ctx, id)
	if err != nil && !errors.IsNotFoundError(err) {
		return nil, errors.Wrap(err, op)
	}
	if u == nil {
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("AuthToken %q not found", id))
	}
	return toProto(u), nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "authtokens.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, errors.Wrap(err, op)
	}
	rows, err := repo.DeleteAuthToken(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(err, op, errors.WithMsg("unable to delete user"))
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeIds []string) ([]*pb.AuthToken, error) {
	repo, err := s.repoFn()
	_ = repo
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListAuthTokens(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	var outUl []*pb.AuthToken
	for _, u := range ul {
		outUl = append(outUl, toProto(u))
	}
	return outUl, nil
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

func toProto(in *authtoken.AuthToken) *pb.AuthToken {
	out := pb.AuthToken{
		Id:                      in.GetPublicId(),
		ScopeId:                 in.GetScopeId(),
		CreatedTime:             in.GetCreateTime().GetTimestamp(),
		UpdatedTime:             in.GetUpdateTime().GetTimestamp(),
		ApproximateLastUsedTime: in.GetApproximateLastAccessTime().GetTimestamp(),
		ExpirationTime:          in.GetExpirationTime().GetTimestamp(),
		UserId:                  in.GetIamUserId(),
		AuthMethodId:            in.GetAuthMethodId(),
		AccountId:               in.GetAuthAccountId(),
	}
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
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
