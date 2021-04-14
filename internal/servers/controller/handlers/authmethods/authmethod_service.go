package authmethods

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/url"
	"strings"

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
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/accounts"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/hashicorp/go-hclog"
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
	IdActions = make(map[auth.SubType]action.ActionSet)

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

func populateCollectionAuthorizedActions(ctx context.Context,
	authResults auth.VerifyResults,
	item *pb.AuthMethod) error {
	res := &perms.Resource{
		ScopeId: authResults.Scope.Id,
		Pin:     item.Id,
	}
	// Range over the defined collections and check permissions against those
	// collections. We use the ID of this scope being returned, not its parent,
	// hence passing in a resource here.
	for k, v := range collectionTypeMap {
		res.Type = k
		acts := authResults.FetchActionSetForType(ctx, k, v, auth.WithResource(res)).Strings()
		if len(acts) > 0 {
			if item.AuthorizedCollectionActions == nil {
				item.AuthorizedCollectionActions = make(map[string]*structpb.ListValue)
			}
			lv, err := structpb.NewList(strutil.StringListToInterfaceList(acts))
			if err != nil {
				return err
			}
			item.AuthorizedCollectionActions[k.String()+"s"] = lv
		}
	}
	return nil
}

// Service handles request as described by the pbs.AuthMethodServiceServer interface.
type Service struct {
	pbs.UnimplementedAuthMethodServiceServer

	kms        *kms.Kms
	pwRepoFn   common.PasswordAuthRepoFactory
	oidcRepoFn common.OidcAuthRepoFactory
	iamRepoFn  common.IamRepoFactory
	atRepoFn   common.AuthTokenRepoFactory

	oidcLogger hclog.Logger
}

// NewService returns a auth method service which handles auth method related requests to boundary.
func NewService(kms *kms.Kms, pwRepoFn common.PasswordAuthRepoFactory, oidcRepoFn common.OidcAuthRepoFactory, iamRepoFn common.IamRepoFactory, atRepoFn common.AuthTokenRepoFactory, opt ...handlers.Option) (Service, error) {
	if kms == nil {
		return Service{}, stderrors.New("nil kms provided")
	}
	if pwRepoFn == nil {
		return Service{}, fmt.Errorf("nil password repository provided")
	}
	if oidcRepoFn == nil {
		return Service{}, fmt.Errorf("nil oidc repository provided")
	}
	if iamRepoFn == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	if atRepoFn == nil {
		return Service{}, fmt.Errorf("nil auth token repository provided")
	}
	s := Service{kms: kms, pwRepoFn: pwRepoFn, oidcRepoFn: oidcRepoFn, iamRepoFn: iamRepoFn, atRepoFn: atRepoFn}
	opts := handlers.GetOpts(opt...)
	if opts.WithLogger != nil {
		s.oidcLogger = opts.WithLogger.Named("oidc")
	}
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

	ul, err := s.listFromRepo(ctx, scopeIds, authResults.UserId == auth.AnonymousUserId)
	if err != nil {
		return nil, err
	}
	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.AuthMethod, 0, len(ul))
	res := &perms.Resource{
		Type: resource.AuthMethod,
	}
	for _, item := range ul {
		item.Scope = scopeInfoMap[item.GetScopeId()]
		res.ScopeId = item.Scope.Id
		item.AuthorizedActions = authResults.FetchActionSetForId(ctx, item.Id, IdActions[auth.SubtypeFromId(item.Id)], auth.WithResource(res)).Strings()
		if len(item.AuthorizedActions) == 0 {
			continue
		}
		if filter.Match(item) {
			finalItems = append(finalItems, item)
			if err := populateCollectionAuthorizedActions(ctx, authResults, item); err != nil {
				return nil, err
			}
		}
	}
	return &pbs.ListAuthMethodsResponse{Items: finalItems}, nil
}

// GetAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) GetAuthMethod(ctx context.Context, req *pbs.GetAuthMethodRequest) (*pbs.GetAuthMethodResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions[auth.SubtypeFromId(u.Id)]).Strings()
	if err := populateCollectionAuthorizedActions(ctx, authResults, u); err != nil {
		return nil, err
	}
	return &pbs.GetAuthMethodResponse{Item: u}, nil
}

// CreateAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) CreateAuthMethod(ctx context.Context, req *pbs.CreateAuthMethodRequest) (*pbs.CreateAuthMethodResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions[auth.SubtypeFromId(u.Id)]).Strings()
	if err := populateCollectionAuthorizedActions(ctx, authResults, u); err != nil {
		return nil, err
	}
	return &pbs.CreateAuthMethodResponse{Item: u, Uri: fmt.Sprintf("auth-methods/%s", u.GetId())}, nil
}

// UpdateAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) UpdateAuthMethod(ctx context.Context, req *pbs.UpdateAuthMethodRequest) (*pbs.UpdateAuthMethodResponse, error) {
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req)
	if err != nil {
		switch {
		case errors.Match(errors.T(errors.InvalidParameter), err):
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "Unable to update auth method: %v.", err)
		default:
			return nil, err
		}
	}
	u.Scope = authResults.Scope
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions[auth.SubtypeFromId(u.Id)]).Strings()
	if err := populateCollectionAuthorizedActions(ctx, authResults, u); err != nil {
		return nil, err
	}
	return &pbs.UpdateAuthMethodResponse{Item: u}, nil
}

// ChangeState implements the interface pbs.AuthMethodServiceServer.
func (s Service) ChangeState(ctx context.Context, req *pbs.ChangeStateRequest) (*pbs.ChangeStateResponse, error) {
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
	am.Scope = authResults.Scope
	am.AuthorizedActions = authResults.FetchActionSetForId(ctx, am.Id, IdActions[auth.OidcSubtype]).Strings()
	if err := populateCollectionAuthorizedActions(ctx, authResults, am); err != nil {
		return nil, err
	}
	return &pbs.ChangeStateResponse{Item: am}, nil
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
	return &pbs.DeleteAuthMethodResponse{}, nil
}

// Authenticate implements the interface pbs.AuthenticationServiceServer.
func (s Service) Authenticate(ctx context.Context, req *pbs.AuthenticateRequest) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).Authenticate"
	if err := validateAuthenticateRequest(req); err != nil {
		return nil, err
	}

	switch auth.SubtypeFromId(req.GetAuthMethodId()) {
	case auth.PasswordSubtype:
		if err := validateAuthenticatePasswordRequest(req); err != nil {
			return nil, err
		}
	case auth.OidcSubtype:
		if err := validateAuthenticateOidcRequest(req); err != nil {
			return nil, err
		}
	}

	authResults := s.authResult(ctx, req.GetAuthMethodId(), action.Authenticate)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	switch auth.SubtypeFromId(req.GetAuthMethodId()) {
	case auth.PasswordSubtype:
		return s.authenticatePassword(ctx, req, &authResults)

	case auth.OidcSubtype:
		return s.authenticateOidc(ctx, req, &authResults)
	}
	return nil, errors.New(errors.Internal, op, "Invalid auth method subtype not caught in validation function.")
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
	tok.AuthorizedActions = authResults.FetchActionSetForId(ctx, tok.Id, authtokens.IdActions, auth.WithResource(res)).Strings()
	return &pbs.AuthenticateLoginResponse{Item: tok, TokenType: req.GetTokenType()}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.AuthMethod, error) {
	var lookupErr error
	var am auth.AuthMethod
	switch auth.SubtypeFromId(id) {
	case auth.PasswordSubtype:
		repo, err := s.pwRepoFn()
		if err != nil {
			return nil, err
		}
		am, lookupErr = repo.LookupAuthMethod(ctx, id)

	case auth.OidcSubtype:
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

	return toAuthMethodProto(am)
}

func (s Service) listFromRepo(ctx context.Context, scopeIds []string, anonUser bool) ([]*pb.AuthMethod, error) {
	oidcRepo, err := s.oidcRepoFn()
	if err != nil {
		return nil, err
	}
	ol, err := oidcRepo.ListAuthMethods(ctx, scopeIds, oidc.WithUnauthenticatedUser(anonUser))
	if err != nil {
		return nil, err
	}
	var outUl []*pb.AuthMethod
	for _, u := range ol {
		ou, err := toAuthMethodProto(u, handlers.WithAnonymousListing(anonUser))
		if err != nil {
			return nil, err
		}
		outUl = append(outUl, ou)
	}

	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
	}
	pl, err := repo.ListAuthMethods(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	for _, u := range pl {
		ou, err := toAuthMethodProto(u, handlers.WithAnonymousListing(anonUser))
		if err != nil {
			return nil, err
		}
		outUl = append(outUl, ou)
	}
	return outUl, nil
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.AuthMethod) (*pb.AuthMethod, error) {
	var out auth.AuthMethod
	switch auth.SubtypeFromType(item.GetType()) {
	case auth.PasswordSubtype:
		am, err := s.createPwInRepo(ctx, scopeId, item)
		if err != nil {
			return nil, err
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create auth method but no error returned from repository.")
		}
		out = am
	case auth.OidcSubtype:
		am, err := s.createOidcInRepo(ctx, scopeId, item)
		if err != nil {
			return nil, err
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create auth method but no error returned from repository.")
		}
		out = am
	}
	return toAuthMethodProto(out)
}

func (s Service) updateInRepo(ctx context.Context, scopeId string, req *pbs.UpdateAuthMethodRequest) (*pb.AuthMethod, error) {
	const op = "authmethod_service.(Service).updateInRepo"
	storageToWire := toAuthMethodProto
	var out auth.AuthMethod
	switch auth.SubtypeFromId(req.GetId()) {
	case auth.PasswordSubtype:
		am, err := s.updatePwInRepo(ctx, scopeId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
		if err != nil {
			return nil, err
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update auth method but no error returned from repository.")
		}
		out = am
	case auth.OidcSubtype:
		am, dryRun, err := s.updateOidcInRepo(ctx, scopeId, req)
		if err != nil {
			return nil, err
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update auth method but no error returned from repository.")
		}
		if dryRun {
			storageToWire = func(in auth.AuthMethod, opt ...handlers.Option) (*pb.AuthMethod, error) {
				am, err := toAuthMethodProto(in)
				if err != nil {
					return nil, errors.Wrap(err, op)
				}
				attrs := &pb.OidcAuthMethodAttributes{}
				if err := handlers.StructToProto(am.GetAttributes(), attrs); err != nil {
					return nil, errors.Wrap(err, op, errors.WithMsg("can't convert from attribute struct to proto"))
				}
				attrs.DryRun = true
				if am.Attributes, err = handlers.ProtoToStruct(attrs); err != nil {
					return nil, errors.Wrap(err, op, errors.WithMsg("can't convert from attribute proto to struct"))
				}
				return am, nil
			}
		}
		out = am
	}
	return storageToWire(out)
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	var rows int
	var dErr error
	switch auth.SubtypeFromId(id) {
	case auth.PasswordSubtype:
		repo, err := s.pwRepoFn()
		if err != nil {
			return false, err
		}
		rows, dErr = repo.DeleteAuthMethod(ctx, scopeId, id)

	case auth.OidcSubtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return false, err
		}
		rows, dErr = repo.DeleteAuthMethod(ctx, id)
	}

	if dErr != nil {
		if errors.IsNotFoundError(dErr) {
			return false, nil
		}
		return false, fmt.Errorf("unable to delete auth method: %w", dErr)
	}

	return rows > 0, nil
}

func (s Service) changeStateInRepo(ctx context.Context, req *pbs.ChangeStateRequest) (*pb.AuthMethod, error) {
	const op = "authmethod_service.(Service).changeStateInRepo"

	switch auth.SubtypeFromId(req.GetId()) {
	case auth.OidcSubtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return nil, err
		}

		attrs := &pbs.OidcChangeStateAttributes{}
		if err := handlers.StructToProto(req.GetAttributes(), attrs); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to parse attributes"))
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
			err = errors.New(errors.InvalidParameter, op, fmt.Sprintf("unrecognized state %q", attrs.GetState()))
		}
		if err != nil {
			return nil, err
		}

		return toAuthMethodProto(am)
	}

	return nil, errors.New(errors.InvalidParameter, op, "Given auth method type does not support changing state")
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	const op = "authmethods.(Service).authResult"
	res := auth.VerifyResults{}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.AuthMethod), auth.WithAction(a)}
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
		case auth.PasswordSubtype:
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
		case auth.OidcSubtype:
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
			res.Error = errors.New(errors.InvalidPublicId, op, "unrecognized auth method type")
			return res
		}
		parentId = authMeth.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toAuthMethodProto(in auth.AuthMethod, opt ...handlers.Option) (*pb.AuthMethod, error) {
	anonListing := handlers.GetOpts(opt...).WithAnonymousListing
	out := &pb.AuthMethod{
		Id:        in.GetPublicId(),
		ScopeId:   in.GetScopeId(),
		IsPrimary: in.GetIsPrimaryAuthMethod(),
	}
	if in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
	}
	if !anonListing {
		out.CreatedTime = in.GetCreateTime().GetTimestamp()
		out.UpdatedTime = in.GetUpdateTime().GetTimestamp()
		out.Version = in.GetVersion()
	}
	switch i := in.(type) {
	case *password.AuthMethod:
		out.Type = auth.PasswordSubtype.String()
		if anonListing {
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
		out.Type = auth.OidcSubtype.String()
		if anonListing {
			break
		}
		attrs := &pb.OidcAuthMethodAttributes{
			ClientId:          wrapperspb.String(i.GetClientId()),
			ClientSecretHmac:  i.ClientSecretHmac,
			IdpCaCerts:        i.GetCertificates(),
			State:             i.GetOperationalState(),
			SigningAlgorithms: i.GetSigningAlgs(),
			AllowedAudiences:  i.GetAudClaims(),
		}
		if i.DisableDiscoveredConfigValidation {
			attrs.DisableDiscoveredConfigValidation = true
		}
		if i.GetIssuer() != "" {
			attrs.Issuer = wrapperspb.String(i.Issuer)
		}
		if len(i.GetApiUrl()) > 0 {
			attrs.ApiUrlPrefix = wrapperspb.String(i.GetApiUrl())
			attrs.CallbackUrl = fmt.Sprintf("%s/v1/auth-methods/%s:authenticate:callback", i.GetApiUrl(), i.GetPublicId())
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
	return out, nil
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
	const op = "authmethod_service.validateGetRequest"
	if req == nil {
		return errors.New(errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, password.AuthMethodPrefix, oidc.AuthMethodPrefix)
}

func validateCreateRequest(req *pbs.CreateAuthMethodRequest) error {
	const op = "authmethod_service.validateCreateRequest"
	if req == nil {
		return errors.New(errors.InvalidParameter, op, "nil request")
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
		case auth.PasswordSubtype:
			attrs := &pb.PasswordAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields[attributesField] = "Attribute fields do not match the expected format."
			}
		case auth.OidcSubtype:
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
					if _, err := oidc.ParseCertificates(attrs.GetIdpCaCerts()...); err != nil {
						badFields[caCertsField] = fmt.Sprintf("Cannot parse CA certificates. %v", err.Error())
					}
				}
			}
		default:
			badFields[typeField] = fmt.Sprintf("This is a required field and must be %q.", auth.PasswordSubtype.String())
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateAuthMethodRequest) error {
	const op = "authmethod_service.validateUpdateRequest"
	if req == nil {
		return errors.New(errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if handlers.MaskContains(req.GetUpdateMask().GetPaths(), isPrimaryField) {
			badFields[isPrimaryField] = "This field is read only."
		}
		switch auth.SubtypeFromId(req.GetId()) {
		case auth.PasswordSubtype:
			if req.GetItem().GetType() != "" && auth.SubtypeFromType(req.GetItem().GetType()) != auth.PasswordSubtype {
				badFields[typeField] = "Cannot modify the resource type."
			}
			attrs := &pb.PasswordAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields[attributesField] = "Attribute fields do not match the expected format."
			}
		case auth.OidcSubtype:
			if req.GetItem().GetType() != "" && auth.SubtypeFromType(req.GetItem().GetType()) != auth.OidcSubtype {
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
					if !strutil.StrListContains([]string{"http", "https"}, iss.Scheme) {
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
				if _, err := oidc.ParseCertificates(attrs.GetIdpCaCerts()...); err != nil {
					badFields[caCertsField] = fmt.Sprintf("Cannot parse CA certificates. %v", err.Error())
				}
			}
		default:
			badFields["id"] = "Incorrectly formatted identifier."
		}
		return badFields
	}, password.AuthMethodPrefix, oidc.AuthMethodPrefix)
}

func validateDeleteRequest(req *pbs.DeleteAuthMethodRequest) error {
	const op = "authmethod_service.validateDeleteRequest"
	if req == nil {
		return errors.New(errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, password.AuthMethodPrefix, oidc.AuthMethodPrefix)
}

func validateListRequest(req *pbs.ListAuthMethodsRequest) error {
	const op = "authmethod_service.validateListRequest"
	if req == nil {
		return errors.New(errors.InvalidParameter, op, "nil request")
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
	const op = "authmethod_service.validateChangeStateRequest"
	if req == nil {
		return errors.New(errors.InvalidParameter, op, "nil request")
	}
	if st := auth.SubtypeFromId(req.GetId()); st != auth.OidcSubtype {
		return handlers.NotFoundErrorf("This endpoint is only available for the %q Auth Method type.", auth.OidcSubtype.String())
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
	const op = "authmethod_service.validateAuthenticateRequest"
	if req == nil {
		return errors.New(errors.InvalidParameter, op, "nil request")
	}

	badFields := make(map[string]string)

	if strings.TrimSpace(req.GetAuthMethodId()) == "" {
		badFields[authMethodIdField] = "This is a required field."
	} else {
		st := auth.SubtypeFromId(req.GetAuthMethodId())
		switch st {
		case auth.PasswordSubtype, auth.OidcSubtype:
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
	const op = "authmethod_service.validateAuthenticateLoginRequest"
	if req == nil {
		return errors.New(errors.InvalidParameter, op, "nil request")
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

func (s Service) convertInternalAuthTokenToApiAuthToken(ctx context.Context, tok *authtoken.AuthToken) (*pba.AuthToken, error) {
	const op = "authmethod_service.convertInternalAuthTokenToApiAuthToken"
	iamRepo, err := s.iamRepoFn()
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil auth token.")
	}
	if tok.Token == "" {
		return nil, errors.New(errors.InvalidParameter, op, "Empty token.")
	}
	if tok.GetPublicId() == "" {
		return nil, errors.New(errors.InvalidParameter, op, "Empty token public ID.")
	}
	if tok.GetScopeId() == "" {
		return nil, errors.New(errors.InvalidParameter, op, "Empty token, scope ID.")
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

func (s Service) convertToAuthenticateResponse(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults, tok *pba.AuthToken) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.convertToAuthenticateResponse"
	if req == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil request.")
	}
	if authResults == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil auth results.")
	}
	if authResults.Scope == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil auth results scope.")
	}
	if authResults.Scope.Id == "" {
		return nil, errors.New(errors.InvalidParameter, op, "Missing auth results scope ID.")
	}
	if tok == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil auth token.")
	}
	res := &perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.AuthToken,
	}
	tok.AuthorizedActions = authResults.FetchActionSetForId(ctx, tok.Id, authtokens.IdActions, auth.WithResource(res)).Strings()
	retAttrs, err := handlers.ProtoToStruct(tok)
	if err != nil {
		return nil, err
	}
	retAttrs.GetFields()[tokenTypeField] = structpb.NewStringValue(req.GetTokenType())

	return &pbs.AuthenticateResponse{Command: req.GetCommand(), Attributes: retAttrs}, nil
}
