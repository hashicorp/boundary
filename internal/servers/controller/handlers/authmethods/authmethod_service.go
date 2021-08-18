package authmethods

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	pba "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	requestauth "github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/accounts"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// general auth method field names
	commandField      = "command"
	versionField      = "version"
	scopeIdField      = "scope_id"
	typeField         = "type"
	attributesField   = "attributes"
	authMethodIdField = "auth_method_id"
	tokenTypeField    = "token_type"
	isPrimaryField    = "is_primary"
)

var (
	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = make(map[subtypes.Subtype]action.ActionSet)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.Create,
		action.List,
	}

	collectionTypeMap = map[resource.Type]action.ActionSet{
		resource.Account: accounts.CollectionActions,
	}
)

// Service handles request as described by the pbs.AuthMethodServiceServer interface.
type Service struct {
	pbs.UnimplementedAuthMethodServiceServer

	kms        *kms.Kms
	pwRepoFn   common.PasswordAuthRepoFactory
	oidcRepoFn common.OidcAuthRepoFactory
	iamRepoFn  common.IamRepoFactory
	atRepoFn   common.AuthTokenRepoFactory
}

// NewService returns a auth method service which handles auth method related requests to boundary.
func NewService(kms *kms.Kms, pwRepoFn common.PasswordAuthRepoFactory, oidcRepoFn common.OidcAuthRepoFactory, iamRepoFn common.IamRepoFactory, atRepoFn common.AuthTokenRepoFactory, opt ...handlers.Option) (Service, error) {
	const op = "authmethods.NewService"
	if kms == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing kms")
	}
	if pwRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing password repository")
	}
	if oidcRepoFn == nil {
		return Service{}, fmt.Errorf("nil oidc repository provided")
	}
	if iamRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing iam repository")
	}
	if atRepoFn == nil {
		return Service{}, fmt.Errorf("nil auth token repository provided")
	}
	s := Service{kms: kms, pwRepoFn: pwRepoFn, oidcRepoFn: oidcRepoFn, iamRepoFn: iamRepoFn, atRepoFn: atRepoFn}

	return s, nil
}

var _ pbs.AuthMethodServiceServer = Service{}

// ListAuthMethods implements the interface pbs.AuthMethodServiceServer.
func (s Service) ListAuthMethods(ctx context.Context, req *pbs.ListAuthMethodsRequest) (*pbs.ListAuthMethodsResponse, error) {
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
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.AuthMethod, req.GetRecursive(), false)
	if err != nil {
		return nil, err
	}
	// If no scopes match, return an empty response
	if len(scopeIds) == 0 {
		return &pbs.ListAuthMethodsResponse{}, nil
	}

	ul, err := s.listFromRepo(ctx, scopeIds, authResults)
	if err != nil {
		return nil, err
	}
	if len(ul) == 0 {
		return &pbs.ListAuthMethodsResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.AuthMethod, 0, len(ul))
	res := perms.Resource{
		Type: resource.AuthMethod,
	}
	for _, am := range ul {
		res.Id = am.GetPublicId()
		res.ScopeId = am.GetScopeId()
		authorizedActions := authResults.FetchActionSetForId(ctx, am.GetPublicId(), IdActions[auth.SubtypeFromId(am.GetPublicId())], requestauth.WithResource(&res)).Strings()
		if len(authorizedActions) == 0 {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[am.GetScopeId()]))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
		}
		if outputFields.Has(globals.AuthorizedCollectionActionsField) {
			collectionActions, err := requestauth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap, authResults.Scope.Id, am.GetPublicId())
			if err != nil {
				return nil, err
			}
			outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
		}

		item, err := toAuthMethodProto(ctx, am, outputOpts...)
		if err != nil {
			return nil, err
		}

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListAuthMethodsResponse{Items: finalItems}, nil
}

// GetAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) GetAuthMethod(ctx context.Context, req *pbs.GetAuthMethodRequest) (*pbs.GetAuthMethodResponse, error) {
	const op = "authmethods.(Service).GetAuthMethod"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	am, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, am.GetPublicId(), IdActions[auth.SubtypeFromId(am.GetPublicId())]).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := requestauth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap, authResults.Scope.Id, am.GetPublicId())
		if err != nil {
			return nil, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	item, err := toAuthMethodProto(ctx, am, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetAuthMethodResponse{Item: item}, nil
}

// CreateAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) CreateAuthMethod(ctx context.Context, req *pbs.CreateAuthMethodRequest) (*pbs.CreateAuthMethodResponse, error) {
	const op = "authmethods.(Service).CreateAuthMethod"

	if err := validateCreateRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	am, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, am.GetPublicId(), IdActions[auth.SubtypeFromId(am.GetPublicId())]).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := requestauth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap, authResults.Scope.Id, am.GetPublicId())
		if err != nil {
			return nil, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	item, err := toAuthMethodProto(ctx, am, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateAuthMethodResponse{Item: item, Uri: fmt.Sprintf("auth-methods/%s", item.GetId())}, nil
}

// UpdateAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) UpdateAuthMethod(ctx context.Context, req *pbs.UpdateAuthMethodRequest) (*pbs.UpdateAuthMethodResponse, error) {
	const op = "authmethods.(Service).UpdateAuthMethod"

	if err := validateUpdateRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	am, dryRun, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req)
	if err != nil {
		switch {
		case errors.Match(errors.T(errors.InvalidParameter), err):
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "Unable to update auth method: %v.", err)
		default:
			return nil, err
		}
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, am.GetPublicId(), IdActions[auth.SubtypeFromId(am.GetPublicId())]).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := requestauth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap, authResults.Scope.Id, am.GetPublicId())
		if err != nil {
			return nil, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	item, err := toAuthMethodProto(ctx, am, outputOpts...)
	if err != nil {
		return nil, err
	}

	if item.GetAttributes() != nil && dryRun {
		item.GetAttributes().Fields["dry_run"] = structpb.NewBoolValue(true)
	}

	return &pbs.UpdateAuthMethodResponse{Item: item}, nil
}

// ChangeState implements the interface pbs.AuthMethodServiceServer.
func (s Service) ChangeState(ctx context.Context, req *pbs.ChangeStateRequest) (*pbs.ChangeStateResponse, error) {
	const op = "authmethods.(Service).ChangeState"

	if err := validateChangeStateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.ChangeState)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	am, err := s.changeStateInRepo(ctx, req)
	if err != nil {
		switch {
		case errors.Match(errors.T(errors.InvalidParameter), err):
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "Unable to change auth method state: %v.", err)
		default:
			return nil, err
		}
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, am.GetPublicId(), IdActions[auth.SubtypeFromId(am.GetPublicId())]).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := requestauth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap, authResults.Scope.Id, am.GetPublicId())
		if err != nil {
			return nil, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	item, err := toAuthMethodProto(ctx, am, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.ChangeStateResponse{Item: item}, nil
}

// DeleteAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) DeleteAuthMethod(ctx context.Context, req *pbs.DeleteAuthMethodRequest) (*pbs.DeleteAuthMethodResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, authResults.Scope.GetId(), req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// Authenticate implements the interface pbs.AuthenticationServiceServer.
func (s Service) Authenticate(ctx context.Context, req *pbs.AuthenticateRequest) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).Authenticate"
	if err := validateAuthenticateRequest(req); err != nil {
		return nil, err
	}

	switch auth.SubtypeFromId(req.GetAuthMethodId()) {
	case password.Subtype:
		if err := validateAuthenticatePasswordRequest(req); err != nil {
			return nil, err
		}
	case oidc.Subtype:
		if err := validateAuthenticateOidcRequest(req); err != nil {
			return nil, err
		}
	}

	authResults := s.authResult(ctx, req.GetAuthMethodId(), action.Authenticate)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	switch auth.SubtypeFromId(req.GetAuthMethodId()) {
	case password.Subtype:
		return s.authenticatePassword(ctx, req, &authResults)

	case oidc.Subtype:
		return s.authenticateOidc(ctx, req, &authResults)
	}
	return nil, errors.New(ctx, errors.Internal, op, "Invalid auth method subtype not caught in validation function.")
}

// Deprecated: use Authenticate
func (s Service) AuthenticateLogin(ctx context.Context, req *pbs.AuthenticateLoginRequest) (*pbs.AuthenticateLoginResponse, error) {
	if err := validateAuthenticateLoginRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetAuthMethodId(), action.Authenticate)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	creds := req.GetCredentials().GetFields()
	tok, err := s.authenticateWithPwRepo(ctx, authResults.Scope.GetId(), req.GetAuthMethodId(), creds[loginNameField].GetStringValue(), creds[passwordField].GetStringValue())
	if err != nil {
		return nil, err
	}
	res := &perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.AuthToken,
	}
	tok.AuthorizedActions = authResults.FetchActionSetForId(ctx, tok.Id, authtokens.IdActions, requestauth.WithResource(res)).Strings()
	return &pbs.AuthenticateLoginResponse{Item: tok, TokenType: req.GetTokenType()}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (auth.AuthMethod, error) {
	var lookupErr error
	var am auth.AuthMethod
	switch auth.SubtypeFromId(id) {
	case password.Subtype:
		repo, err := s.pwRepoFn()
		if err != nil {
			return nil, err
		}
		am, lookupErr = repo.LookupAuthMethod(ctx, id)

	case oidc.Subtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return nil, err
		}
		am, lookupErr = repo.LookupAuthMethod(ctx, id)

	default:
		return nil, handlers.NotFoundErrorf("Unrecognized id.")
	}

	if lookupErr != nil {
		if errors.IsNotFoundError(lookupErr) {
			return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
		}
		return nil, lookupErr
	}
	if am == nil {
		return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
	}

	return am, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeIds []string, authResults requestauth.VerifyResults) ([]auth.AuthMethod, error) {
	const op = "authmethods.(Service).listFromRepo"
	reqCtx, ok := requests.RequestContextFromCtx(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	var outUl []auth.AuthMethod

	oidcRepo, err := s.oidcRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	ol, err := oidcRepo.ListAuthMethods(ctx, scopeIds, oidc.WithUnauthenticatedUser(reqCtx.UserId == requestauth.AnonymousUserId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	for _, item := range ol {
		outUl = append(outUl, item)
	}

	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	pl, err := repo.ListAuthMethods(ctx, scopeIds)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	for _, item := range pl {
		outUl = append(outUl, item)
	}
	return outUl, nil
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.AuthMethod) (auth.AuthMethod, error) {
	const op = "authmethods.(Service).createInRepo"
	var out auth.AuthMethod
	switch auth.SubtypeFromType(item.GetType()) {
	case password.Subtype:
		am, err := s.createPwInRepo(ctx, scopeId, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create auth method but no error returned from repository.")
		}
		out = am
	case oidc.Subtype:
		am, err := s.createOidcInRepo(ctx, scopeId, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create auth method but no error returned from repository.")
		}
		out = am
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId string, req *pbs.UpdateAuthMethodRequest) (auth.AuthMethod, bool, error) {
	const op = "authmethods.(Service).updateInRepo"

	var am auth.AuthMethod
	var dryRun bool

	switch auth.SubtypeFromId(req.GetId()) {
	case password.Subtype:
		pam, err := s.updatePwInRepo(ctx, scopeId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
		if err != nil {
			return nil, false, errors.Wrap(ctx, err, op)
		}
		if pam == nil {
			return nil, false, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update auth method but no error returned from repository.")
		}
		am = pam

	case oidc.Subtype:
		oam, dr, err := s.updateOidcInRepo(ctx, scopeId, req)
		if err != nil {
			return nil, false, errors.Wrap(ctx, err, op)
		}
		if oam == nil {
			return nil, false, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update auth method but no error returned from repository.")
		}
		am = oam
		dryRun = dr
	}

	return am, dryRun, nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	const op = "authmethods.(Service).deleteFromRepo"
	var rows int
	var dErr error
	switch auth.SubtypeFromId(id) {
	case password.Subtype:
		repo, err := s.pwRepoFn()
		if err != nil {
			return false, errors.Wrap(ctx, err, op)
		}
		rows, dErr = repo.DeleteAuthMethod(ctx, scopeId, id)

	case oidc.Subtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return false, errors.Wrap(ctx, err, op)
		}
		rows, dErr = repo.DeleteAuthMethod(ctx, id)
	}

	if dErr != nil {
		if errors.IsNotFoundError(dErr) {
			return false, nil
		}
		return false, errors.Wrap(ctx, dErr, op, errors.WithMsg("unable to delete auth method"))
	}

	return rows > 0, nil
}

func (s Service) changeStateInRepo(ctx context.Context, req *pbs.ChangeStateRequest) (auth.AuthMethod, error) {
	const op = "authmethod_service.(Service).changeStateInRepo"

	switch auth.SubtypeFromId(req.GetId()) {
	case oidc.Subtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return nil, err
		}

		attrs := &pbs.OidcChangeStateAttributes{}
		if err := handlers.StructToProto(req.GetAttributes(), attrs); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to parse attributes"))
		}

		var opts []oidc.Option
		if attrs.GetDisableDiscoveredConfigValidation() {
			opts = append(opts, oidc.WithForce())
		}

		var am *oidc.AuthMethod
		switch oidcStateMap[attrs.GetState()] {
		case inactiveState:
			am, err = repo.MakeInactive(ctx, req.GetId(), req.GetVersion())
		case privateState:
			am, err = repo.MakePrivate(ctx, req.GetId(), req.GetVersion(), opts...)
		case publicState:
			am, err = repo.MakePublic(ctx, req.GetId(), req.GetVersion(), opts...)
		default:
			err = errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unrecognized state %q", attrs.GetState()))
		}
		if err != nil {
			return nil, err
		}

		return am, nil
	}

	return nil, errors.New(ctx, errors.InvalidParameter, op, "Given auth method type does not support changing state")
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) requestauth.VerifyResults {
	const op = "authmethods.(Service).authResult"
	res := requestauth.VerifyResults{}

	var parentId string
	opts := []requestauth.Option{requestauth.WithType(resource.AuthMethod), requestauth.WithAction(a)}
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
		var authMeth auth.AuthMethod
		switch auth.SubtypeFromId(id) {
		case password.Subtype:
			repo, err := s.pwRepoFn()
			if err != nil {
				res.Error = err
				return res
			}
			am, err := repo.LookupAuthMethod(ctx, id)
			if err != nil {
				res.Error = err
				return res
			}
			if am == nil {
				res.Error = handlers.NotFoundError()
				return res
			}
			authMeth = am
		case oidc.Subtype:
			repo, err := s.oidcRepoFn()
			if err != nil {
				res.Error = err
				return res
			}
			am, err := repo.LookupAuthMethod(ctx, id)
			if err != nil {
				res.Error = err
				return res
			}
			if am == nil {
				res.Error = handlers.NotFoundError()
				return res
			}
			authMeth = am
		default:
			res.Error = errors.New(ctx, errors.InvalidPublicId, op, "unrecognized auth method type")
			return res
		}
		parentId = authMeth.GetScopeId()
		opts = append(opts, requestauth.WithId(id))
	}
	opts = append(opts, requestauth.WithScopeId(parentId))
	return requestauth.Verify(ctx, opts...)
}

func toAuthMethodProto(ctx context.Context, in auth.AuthMethod, opt ...handlers.Option) (*pb.AuthMethod, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building auth method proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.AuthMethod{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetScopeId()
	}
	if outputFields.Has(globals.IsPrimaryField) {
		out.IsPrimary = in.GetIsPrimaryAuthMethod()
	}
	if outputFields.Has(globals.DescriptionField) && in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if outputFields.Has(globals.NameField) && in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
	}
	if outputFields.Has(globals.CreatedTimeField) {
		out.CreatedTime = in.GetCreateTime().GetTimestamp()
	}
	if outputFields.Has(globals.UpdatedTimeField) {
		out.UpdatedTime = in.GetUpdateTime().GetTimestamp()
	}
	if outputFields.Has(globals.VersionField) {
		out.Version = in.GetVersion()
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		out.AuthorizedCollectionActions = opts.WithAuthorizedCollectionActions
	}
	switch i := in.(type) {
	case *password.AuthMethod:
		if outputFields.Has(globals.TypeField) {
			out.Type = password.Subtype.String()
		}
		if !outputFields.Has(globals.AttributesField) {
			break
		}
		st, err := handlers.ProtoToStruct(&pb.PasswordAuthMethodAttributes{
			MinLoginNameLength: i.GetMinLoginNameLength(),
			MinPasswordLength:  i.GetMinPasswordLength(),
		})
		if err != nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed building password attribute struct: %v", err)
		}
		out.Attributes = st
	case *oidc.AuthMethod:
		if outputFields.Has(globals.TypeField) {
			out.Type = oidc.Subtype.String()
		}
		if !outputFields.Has(globals.AttributesField) {
			break
		}
		attrs := &pb.OidcAuthMethodAttributes{
			ClientId:          wrapperspb.String(i.GetClientId()),
			ClientSecretHmac:  i.ClientSecretHmac,
			IdpCaCerts:        i.GetCertificates(),
			State:             i.GetOperationalState(),
			SigningAlgorithms: i.GetSigningAlgs(),
			AllowedAudiences:  i.GetAudClaims(),
			ClaimsScopes:      i.GetClaimsScopes(),
			AccountClaimMaps:  i.GetAccountClaimMaps(),
		}
		if i.DisableDiscoveredConfigValidation {
			attrs.DisableDiscoveredConfigValidation = true
		}
		if i.GetIssuer() != "" {
			attrs.Issuer = wrapperspb.String(i.Issuer)
		}
		if len(i.GetApiUrl()) > 0 {
			attrs.ApiUrlPrefix = wrapperspb.String(i.GetApiUrl())
			attrs.CallbackUrl = fmt.Sprintf("%s/v1/auth-methods/oidc:authenticate:callback", i.GetApiUrl())
		}
		switch i.GetMaxAge() {
		case 0:
		case -1:
			attrs.MaxAge = wrapperspb.UInt32(0)
		default:
			attrs.MaxAge = wrapperspb.UInt32(uint32(i.GetMaxAge()))
		}

		st, err := handlers.ProtoToStruct(attrs)
		if err != nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed building oidc attribute struct: %v", err)
		}
		out.Attributes = st
	}
	return &out, nil
}

func toAuthTokenProto(t *authtoken.AuthToken) *pba.AuthToken {
	return &pba.AuthToken{
		Id:                      t.GetPublicId(),
		Token:                   t.GetToken(),
		UserId:                  t.GetIamUserId(),
		AuthMethodId:            t.GetAuthMethodId(),
		AccountId:               t.GetAuthAccountId(),
		CreatedTime:             t.GetCreateTime().GetTimestamp(),
		UpdatedTime:             t.GetUpdateTime().GetTimestamp(),
		ApproximateLastUsedTime: t.GetApproximateLastAccessTime().GetTimestamp(),
		ExpirationTime:          t.GetExpirationTime().GetTimestamp(),
	}
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetAuthMethodRequest) error {
	const op = "authmethod.validateGetRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "Missing request")
	}
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, password.AuthMethodPrefix, oidc.AuthMethodPrefix)
}

func validateCreateRequest(ctx context.Context, req *pbs.CreateAuthMethodRequest) error {
	const op = "authmethod.validateCreateRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "Missing request")
	}
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetScopeId()), scope.Org.Prefix()) &&
			scope.Global.String() != req.GetItem().GetScopeId() {
			badFields[scopeIdField] = "This field must be 'global' or a valid org scope id."
		}
		if req.GetItem().GetIsPrimary() {
			badFields[isPrimaryField] = "This field is read only."
		}
		switch auth.SubtypeFromType(req.GetItem().GetType()) {
		case password.Subtype:
			attrs := &pb.PasswordAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields[attributesField] = "Attribute fields do not match the expected format."
			}
		case oidc.Subtype:
			attrs := &pb.OidcAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields[attributesField] = "Attribute fields do not match the expected format."
			} else {
				if attrs.GetIssuer().GetValue() != "" {
					iss, err := url.Parse(attrs.GetIssuer().GetValue())
					if err != nil {
						badFields[issuerField] = fmt.Sprintf("Cannot be parsed as a url. %v", err)
					}
					if !strutil.StrListContains([]string{"http", "https"}, iss.Scheme) {
						badFields[issuerField] = fmt.Sprintf("Must have schema %q or %q specified", "http", "https")
					}
				}
				if attrs.GetDisableDiscoveredConfigValidation() {
					badFields[disableDiscoveredConfigValidationField] = "Field is not allowed at create time."
				}
				if attrs.GetClientId().GetValue() == "" {
					badFields[clientIdField] = "Field required for creating an OIDC auth method."
				}
				if attrs.GetClientSecret().GetValue() == "" {
					badFields[clientSecretField] = "Field required for creating an OIDC auth method."
				}
				if attrs.GetClientSecretHmac() != "" {
					badFields[clientSecretHmacField] = "Field is read only."
				}
				if attrs.GetState() != "" {
					badFields[stateField] = "Field is read only."
				}
				if attrs.GetCallbackUrl() != "" {
					badFields[callbackUrlField] = "Field is read only."
				}
				if len(attrs.GetSigningAlgorithms()) > 0 {
					for _, sa := range attrs.GetSigningAlgorithms() {
						if !oidc.SupportedAlgorithm(oidc.Alg(sa)) {
							badFields[signingAlgorithmField] = fmt.Sprintf("Contains unsupported algorithm %q", sa)
							break
						}
					}
				}
				if strings.TrimSpace(attrs.GetApiUrlPrefix().GetValue()) == "" {
					// TODO: When we start accepting the address used in the request make this an optional field.
					badFields[apiUrlPrefixField] = "This field is required."
				} else {
					if cu, err := url.Parse(attrs.GetApiUrlPrefix().GetValue()); err != nil || (cu.Scheme != "http" && cu.Scheme != "https") || cu.Host == "" {
						badFields[apiUrlPrefixField] = fmt.Sprintf("%q cannot be parsed as a url.", attrs.GetApiUrlPrefix().GetValue())
					}
				}
				if len(attrs.GetIdpCaCerts()) > 0 {
					if _, err := oidc.ParseCertificates(ctx, attrs.GetIdpCaCerts()...); err != nil {
						badFields[idpCaCertsField] = fmt.Sprintf("Cannot parse CA certificates. %v", err.Error())
					}
				}
				if len(attrs.GetClaimsScopes()) > 0 {
					for _, cs := range attrs.GetClaimsScopes() {
						if cs == oidc.DefaultClaimsScope {
							badFields[claimsScopesField] = fmt.Sprintf("%s is the default scope and cannot be added as optional %q", oidc.DefaultClaimsScope, cs)
							break
						}
					}
				}
				if len(attrs.GetAccountClaimMaps()) > 0 {
					acm, err := oidc.ParseAccountClaimMaps(ctx, attrs.GetAccountClaimMaps()...)
					if err != nil {
						badFields[accountClaimMapsField] = fmt.Sprintf("Contains invalid map %q", err.Error())
					}
					foundTo := make(map[string]bool, len(attrs.GetAccountClaimMaps()))
					for _, m := range acm {
						if foundTo[m.To] {
							badFields[accountClaimMapsField] = fmt.Sprintf("%s=%s contains invalid map - multiple maps to the same Boundary to-claim %s", m.From, m.To, m.To)
						}
						foundTo[m.To] = true
					}
				}
			}
		default:
			badFields[typeField] = fmt.Sprintf("This is a required field and must be %q.", password.Subtype.String())
		}
		return badFields
	})
}

func validateUpdateRequest(ctx context.Context, req *pbs.UpdateAuthMethodRequest) error {
	const op = "authmethod.validateUpdateRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing request")
	}
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if handlers.MaskContains(req.GetUpdateMask().GetPaths(), isPrimaryField) {
			badFields[isPrimaryField] = "This field is read only."
		}
		switch auth.SubtypeFromId(req.GetId()) {
		case password.Subtype:
			if req.GetItem().GetType() != "" && auth.SubtypeFromType(req.GetItem().GetType()) != password.Subtype {
				badFields[typeField] = "Cannot modify the resource type."
			}
			attrs := &pb.PasswordAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields[attributesField] = "Attribute fields do not match the expected format."
			}
		case oidc.Subtype:
			if req.GetItem().GetType() != "" && auth.SubtypeFromType(req.GetItem().GetType()) != oidc.Subtype {
				badFields[typeField] = "Cannot modify the resource type."
			}
			attrs := &pb.OidcAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields[attributesField] = "Attribute fields do not match the expected format."
			}
			if attrs.DryRun && attrs.DisableDiscoveredConfigValidation {
				badFields[disableDiscoveredConfigValidationField] = "This field cannot be set to true with dry_run."
			}

			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), apiUrlPrefixField) {
				// TODO: When we start accepting the address used in the request make this an optional field.
				if strings.TrimSpace(attrs.GetApiUrlPrefix().GetValue()) == "" {
					badFields[apiUrlPrefixField] = "This field should not be set to empty."
				}
				if cu, err := url.Parse(attrs.GetApiUrlPrefix().GetValue()); err != nil || (cu.Scheme != "http" && cu.Scheme != "https") || cu.Host == "" {
					badFields[apiUrlPrefixField] = fmt.Sprintf("%q cannot be parsed as a url.", attrs.GetApiUrlPrefix().GetValue())
				}
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), issuerField) {
				if attrs.GetIssuer().GetValue() != "" {
					iss, err := url.Parse(attrs.GetIssuer().GetValue())
					if err != nil {
						badFields[issuerField] = fmt.Sprintf("Cannot be parsed as a url. %v", err)
					}
					if iss != nil && !strutil.StrListContains([]string{"http", "https"}, iss.Scheme) {
						badFields[issuerField] = fmt.Sprintf("Must have schema %q or %q specified", "http", "https")
					}
				}
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), apiUrlPrefixField) {
				if attrs.GetApiUrlPrefix().GetValue() != "" {
					cu, err := url.Parse(attrs.GetApiUrlPrefix().GetValue())
					if err != nil || cu.Host == "" {
						badFields[apiUrlPrefixField] = fmt.Sprintf("%q cannot be parsed as a url.", attrs.GetApiUrlPrefix().GetValue())
					}
					if !strutil.StrListContains([]string{"http", "https"}, cu.Scheme) {
						badFields[apiUrlPrefixField] = fmt.Sprintf("Must have schema %q or %q specified", "http", "https")
					}
				}
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), clientSecretField) && attrs.GetClientSecret().GetValue() == "" {
				badFields[clientSecretField] = "Can change but cannot unset this field."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), clientIdField) && attrs.GetClientId().GetValue() == "" {
				badFields[clientIdField] = "Can change but cannot unset this field."
			}

			if attrs.GetClientSecretHmac() != "" {
				badFields[clientSecretHmacField] = "Field is read only."
			}
			if attrs.GetState() != "" {
				badFields[stateField] = "Field is read only."
			}
			if attrs.GetCallbackUrl() != "" {
				badFields[callbackUrlField] = "Field is read only."
			}

			if len(attrs.GetSigningAlgorithms()) > 0 {
				for _, sa := range attrs.GetSigningAlgorithms() {
					if !oidc.SupportedAlgorithm(oidc.Alg(sa)) {
						badFields[signingAlgorithmField] = fmt.Sprintf("Contains unsupported algorithm %q", sa)
						break
					}
				}
			}
			if len(attrs.GetIdpCaCerts()) > 0 {
				if _, err := oidc.ParseCertificates(ctx, attrs.GetIdpCaCerts()...); err != nil {
					badFields[idpCaCertsField] = fmt.Sprintf("Cannot parse CA certificates. %v", err.Error())
				}
			}
			if len(attrs.GetClaimsScopes()) > 0 {
				for _, cs := range attrs.GetClaimsScopes() {
					if cs == oidc.DefaultClaimsScope {
						badFields[claimsScopesField] = fmt.Sprintf("%s is the default scope and cannot be added as optional %q", oidc.DefaultClaimsScope, cs)
						break
					}
				}
			}
			if len(attrs.GetAccountClaimMaps()) > 0 {
				acm, err := oidc.ParseAccountClaimMaps(ctx, attrs.GetAccountClaimMaps()...)
				if err != nil {
					badFields[accountClaimMapsField] = fmt.Sprintf("Contains invalid map %q", err.Error())
				} else {
					foundTo := make(map[string]bool, len(attrs.GetAccountClaimMaps()))
					for _, m := range acm {
						if foundTo[m.To] {
							badFields[accountClaimMapsField] = fmt.Sprintf("%s=%s contains invalid map - multiple maps to the same Boundary to-claim %s", m.From, m.To, m.To)
						}
						foundTo[m.To] = true

						to, err := oidc.ConvertToAccountToClaim(ctx, m.To)
						if err != nil {
							badFields[accountClaimMapsField] = fmt.Sprintf("%s=%s contains invalid map %q", m.From, m.To, err.Error())
							break
						}
						if to == oidc.ToSubClaim {
							badFields[accountClaimMapsField] = fmt.Sprintf("%s=%s contains invalid map: not allowed to update sub claim maps", m.From, m.To)
							break
						}
					}
				}
			}
		default:
			badFields["id"] = "Incorrectly formatted identifier."
		}
		return badFields
	}, password.AuthMethodPrefix, oidc.AuthMethodPrefix)
}

func validateDeleteRequest(req *pbs.DeleteAuthMethodRequest) error {
	const op = "authmethod.validateDeleteRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "Missing request")
	}
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, password.AuthMethodPrefix, oidc.AuthMethodPrefix)
}

func validateListRequest(req *pbs.ListAuthMethodsRequest) error {
	const op = "authmethod.validateListRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "Missing request")
	}
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields[scopeIdField] = "This field must be 'global' or a valid org scope id."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateChangeStateRequest(req *pbs.ChangeStateRequest) error {
	const op = "authmethod.validateChangeStateRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "Missing request")
	}
	if st := auth.SubtypeFromId(req.GetId()); st != oidc.Subtype {
		return handlers.NotFoundErrorf("This endpoint is only available for the %q Auth Method type.", oidc.Subtype.String())
	}
	badFields := make(map[string]string)
	if req.GetVersion() == 0 {
		badFields[versionField] = "Resource version is required."
	}

	attrs := &pbs.OidcChangeStateAttributes{}
	if err := handlers.StructToProto(req.GetAttributes(), attrs); err != nil {
		badFields[attributesField] = "Attribute fields do not match the expected format."
	}
	switch oidcStateMap[attrs.GetState()] {
	case inactiveState, privateState, publicState:
	default:
		badFields[stateField] = fmt.Sprintf("Only supported values are %q, %q, or %q.", inactiveState.String(), privateState.String(), publicState.String())
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid fields provided in request.", badFields)
	}
	return nil
}

func validateAuthenticateRequest(req *pbs.AuthenticateRequest) error {
	const op = "authmethod.validateAuthenticateRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "Missing request")
	}

	badFields := make(map[string]string)

	if strings.TrimSpace(req.GetAuthMethodId()) == "" {
		badFields[authMethodIdField] = "This is a required field."
	} else {
		st := auth.SubtypeFromId(req.GetAuthMethodId())
		switch st {
		case password.Subtype, oidc.Subtype:
		default:
			badFields[authMethodIdField] = "Unknown auth method type."
		}
	}

	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid fields provided in request.", badFields)
	}

	return nil
}

// Deprecated; remove when AuthenticateLogin is removed
func validateAuthenticateLoginRequest(req *pbs.AuthenticateLoginRequest) error {
	const op = "authmethod.validateAuthenticateLoginRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "Missing request")
	}
	badFields := make(map[string]string)
	if strings.TrimSpace(req.GetAuthMethodId()) == "" {
		badFields[authMethodIdField] = "This is a required field."
	} else if !handlers.ValidId(handlers.Id(req.GetAuthMethodId()), password.AuthMethodPrefix) {
		badFields[authMethodIdField] = "Invalid formatted identifier."
	}
	if req.GetCredentials() == nil {
		badFields["credentials"] = "This is a required field."
	}
	creds := req.GetCredentials().GetFields()
	if _, ok := creds[loginNameField]; !ok {
		badFields["credentials.login_name"] = "This is a required field."
	}
	if _, ok := creds[passwordField]; !ok {
		badFields["credentials.password"] = "This is a required field."
	}
	tType := strings.ToLower(strings.TrimSpace(req.GetTokenType()))
	if tType != "" && tType != "token" && tType != "cookie" {
		badFields[tokenTypeField] = `The only accepted types are "token" and "cookie".`
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid fields provided in request.", badFields)
	}
	return nil
}

func (s Service) ConvertInternalAuthTokenToApiAuthToken(ctx context.Context, tok *authtoken.AuthToken) (*pba.AuthToken, error) {
	const op = "authmethod.ConvertInternalAuthTokenToApiAuthToken"
	iamRepo, err := s.iamRepoFn()
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth token.")
	}
	if tok.Token == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Empty token.")
	}
	if tok.GetPublicId() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Empty token public ID.")
	}
	if tok.GetScopeId() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Empty token, scope ID.")
	}
	token, err := authtoken.EncryptToken(ctx, s.kms, tok.GetScopeId(), tok.GetPublicId(), tok.GetToken())
	if err != nil {
		return nil, err
	}

	tok.Token = tok.GetPublicId() + "_" + token
	prot := toAuthTokenProto(tok)

	scp, err := iamRepo.LookupScope(ctx, tok.GetScopeId())
	if err != nil {
		return nil, err
	}
	if scp == nil {
		return nil, err
	}
	prot.Scope = &scopes.ScopeInfo{
		Id:            scp.GetPublicId(),
		Type:          scp.GetType(),
		ParentScopeId: scp.GetParentId(),
	}

	return prot, nil
}

func (s Service) convertToAuthenticateResponse(ctx context.Context, req *pbs.AuthenticateRequest, authResults *requestauth.VerifyResults, tok *pba.AuthToken) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod.convertToAuthenticateResponse"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Missing request.")
	}
	if authResults == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Missing auth results.")
	}
	if authResults.Scope == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Missing auth results scope.")
	}
	if authResults.Scope.Id == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Missing auth results scope ID.")
	}
	if tok == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Missing auth token.")
	}
	res := &perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.AuthToken,
	}
	tok.AuthorizedActions = authResults.FetchActionSetForId(ctx, tok.Id, authtokens.IdActions, requestauth.WithResource(res)).Strings()
	retAttrs, err := handlers.ProtoToStruct(tok)
	if err != nil {
		return nil, err
	}
	retAttrs.GetFields()[tokenTypeField] = structpb.NewStringValue(req.GetTokenType())

	return &pbs.AuthenticateResponse{Command: req.GetCommand(), Attributes: retAttrs}, nil
}
