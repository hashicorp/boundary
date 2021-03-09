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
	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	pba "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	loginNameKey = "login_name"
	pwKey        = "password"
)

var (
	maskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.ActionSet{
		action.Read,
		action.Update,
		action.Delete,
		action.Authenticate,
	}

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

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.AuthMethod{}, &pb.AuthMethod{}, &pb.PasswordAuthMethodAttributes{}); err != nil {
		panic(err)
	}
}

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
}

// NewService returns a auth method service which handles auth method related requests to boundary.
func NewService(kms *kms.Kms, pwRepoFn common.PasswordAuthRepoFactory, oidcRepoFn common.OidcAuthRepoFactory, iamRepoFn common.IamRepoFactory, atRepoFn common.AuthTokenRepoFactory) (Service, error) {
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
	return Service{kms: kms, pwRepoFn: pwRepoFn, oidcRepoFn: oidcRepoFn, iamRepoFn: iamRepoFn, atRepoFn: atRepoFn}, nil
}

var _ pbs.AuthMethodServiceServer = Service{}

// ListAuthMethods implements the interface pbs.AuthMethodServiceServer.
func (s Service) ListAuthMethods(ctx context.Context, req *pbs.ListAuthMethodsRequest) (*pbs.ListAuthMethodsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	scopeIds, scopeInfoMap, err := scopeids.GetScopeIds(
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), req.GetRecursive())
	if err != nil {
		return nil, err
	}

	ul, err := s.listFromRepo(ctx, scopeIds)
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
		item.AuthorizedActions = authResults.FetchActionSetForId(ctx, item.Id, IdActions, auth.WithResource(res)).Strings()
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
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions).Strings()
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
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions).Strings()
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
	u, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions).Strings()
	if err := populateCollectionAuthorizedActions(ctx, authResults, u); err != nil {
		return nil, err
	}
	return &pbs.UpdateAuthMethodResponse{Item: u}, nil
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
//
// Deprecated in favor of AuthenticateLogin
func (s Service) Authenticate(ctx context.Context, req *pbs.AuthenticateRequest) (*pbs.AuthenticateResponse, error) {
	if err := validateAuthenticateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetAuthMethodId(), action.Authenticate)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	creds := req.GetCredentials().GetFields()
	tok, err := s.authenticateWithRepo(ctx, authResults.Scope.GetId(), req.GetAuthMethodId(), creds[loginNameKey].GetStringValue(), creds[pwKey].GetStringValue())
	if err != nil {
		return nil, err
	}
	res := &perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.AuthToken,
	}
	tok.AuthorizedActions = authResults.FetchActionSetForId(ctx, tok.Id, authtokens.IdActions, auth.WithResource(res)).Strings()
	return &pbs.AuthenticateResponse{Item: tok, TokenType: req.GetTokenType()}, nil
}

// AuthenticateLogin implements the interface pbs.AuthenticationServiceServer.
func (s Service) AuthenticateLogin(ctx context.Context, req *pbs.AuthenticateLoginRequest) (*pbs.AuthenticateLoginResponse, error) {
	if err := validateAuthenticateLoginRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetAuthMethodId(), action.Authenticate)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	creds := req.GetCredentials().GetFields()
	tok, err := s.authenticateWithRepo(ctx, authResults.Scope.GetId(), req.GetAuthMethodId(), creds[loginNameKey].GetStringValue(), creds[pwKey].GetStringValue())
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
	var am auth.AuthMethod
	switch auth.SubtypeFromId(id) {
	case auth.PasswordSubtype:
		repo, err := s.pwRepoFn()
		if err != nil {
			return nil, err
		}
		u, err := repo.LookupAuthMethod(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
			}
			return nil, err
		}
		if u == nil {
			return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
		}
		am = u
	case auth.OidcSubtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return nil, err
		}
		u, err := repo.LookupAuthMethod(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
			}
			return nil, err
		}
		if u == nil {
			return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
		}
		am = u
	default:
		return nil, handlers.NotFoundErrorf("Unrecognized id.")
	}
	return toAuthMethodProto(am)
}

func (s Service) listFromRepo(ctx context.Context, scopeIds []string) ([]*pb.AuthMethod, error) {
	oidcRepo, err := s.oidcRepoFn()
	if err != nil {
		return nil, err
	}
	ol, err := oidcRepo.ListAuthMethods(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	var outUl []*pb.AuthMethod
	for _, u := range ol {
		ou, err := toAuthMethodProto(u)
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
		ou, err := toAuthMethodProto(u)
		if err != nil {
			return nil, err
		}
		outUl = append(outUl, ou)
	}
	return outUl, nil
}

// createPwInRepo creates a password auth method in a repo and returns the result.
// This method should never return a nil AuthMethod without returning an error.
func (s Service) createPwInRepo(ctx context.Context, scopeId string, item *pb.AuthMethod) (*password.AuthMethod, error) {
	var opts []password.Option
	if item.GetName() != nil {
		opts = append(opts, password.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, password.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := password.NewAuthMethod(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method for creation: %v.", err)
	}
	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateAuthMethod(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("unable to create auth method: %w", err)
	}
	return out, err
}

// createOidcInRepo creates an oidc auth method in a repo and returns the result.
// This method should never return a nil AuthMethod without returning an error.
func (s Service) createOidcInRepo(ctx context.Context, scopeId string, item *pb.AuthMethod) (*oidc.AuthMethod, error) {
	attrs := &pb.OidcAuthMethodAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), attrs); err != nil {
		return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
			map[string]string{"attributes": "Attribute fields do not match the expected format."})
	}
	clientId := attrs.GetClientId().GetValue()
	clientSecret := oidc.ClientSecret(attrs.GetClientSecret().GetValue())

	var opts []oidc.Option
	if item.GetName() != nil {
		opts = append(opts, oidc.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, oidc.WithDescription(item.GetDescription().GetValue()))
	}

	var discoveryUrl *url.URL
	if ds := attrs.GetDiscoveryUrl().GetValue(); ds != "" {
		var err error
		if discoveryUrl, err = url.Parse(ds); err != nil {
			return nil, err
		}
		// remove everything except for protocol, hostname, and port.
		if discoveryUrl, err = discoveryUrl.Parse("/"); err != nil {
			return nil, err
		}
	}

	// MaxAge can be -1 or a positive integer.
	if attrs.GetMaxAge().GetValue() != 0 {
		opts = append(opts, oidc.WithMaxAge(int(attrs.GetMaxAge().GetValue())))
	}
	var signAlgs []oidc.Alg
	for _, a := range attrs.GetSigningAlgorithms() {
		signAlgs = append(signAlgs, oidc.Alg(a))
	}
	if len(signAlgs) > 0 {
		opts = append(opts, oidc.WithSigningAlgs(signAlgs...))
	}
	if len(attrs.GetAudiences()) > 0 {
		opts = append(opts, oidc.WithAudClaims(attrs.GetAudiences()...))
	}

	var cbs []*url.URL
	for _, cbUrl := range attrs.GetCallbackUrlPrefixes() {
		cbu, err := url.Parse(cbUrl)
		if err != nil {
			return nil, handlers.InvalidArgumentErrorf("Error in provided request",
				map[string]string{"attributes.callback_url_prefixes": "Unparseable url"})
		}
		cbs = append(cbs, cbu)
	}
	if len(cbs) > 0 {
		opts = append(opts, oidc.WithCallbackUrls(cbs...))
	}

	if len(attrs.GetCertificates()) > 0 {
		certs, err := oidc.ParseCertificates(attrs.GetCertificates()...)
		if err != nil {
			return nil, err
		}
		opts = append(opts, oidc.WithCertificates(certs...))
	}

	u, err := oidc.NewAuthMethod(scopeId, discoveryUrl, clientId, clientSecret, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method for creation: %v.", err)
	}
	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateAuthMethod(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("unable to create auth method: %w", err)
	}
	return out, nil
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

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.AuthMethod) (*pb.AuthMethod, error) {
	var opts []password.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, password.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, password.WithName(name.GetValue()))
	}
	u, err := password.NewAuthMethod(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method for update: %v.", err)
	}

	pwAttrs := &pb.PasswordAuthMethodAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), pwAttrs); err != nil {
		return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
			map[string]string{"attributes": "Attribute fields do not match the expected format."})
	}
	if pwAttrs.GetMinLoginNameLength() != 0 {
		u.MinLoginNameLength = pwAttrs.GetMinLoginNameLength()
	}
	if pwAttrs.GetMinPasswordLength() != 0 {
		u.MinPasswordLength = pwAttrs.GetMinPasswordLength()
	}
	version := item.GetVersion()

	u.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateAuthMethod(ctx, u, version, dbMask)
	if err != nil {
		return nil, fmt.Errorf("unable to update auth method: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist or incorrect version provided.", id)
	}
	return toAuthMethodProto(out)
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	repo, err := s.pwRepoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteAuthMethod(ctx, scopeId, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, fmt.Errorf("unable to delete auth method: %w", err)
	}
	return rows > 0, nil
}

func (s Service) authenticateWithRepo(ctx context.Context, scopeId, authMethodId, loginName, pw string) (*pba.AuthToken, error) {
	iamRepo, err := s.iamRepoFn()
	if err != nil {
		return nil, err
	}
	atRepo, err := s.atRepoFn()
	if err != nil {
		return nil, err
	}
	pwRepo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
	}

	acct, err := pwRepo.Authenticate(ctx, scopeId, authMethodId, loginName, pw)
	if err != nil {
		return nil, err
	}
	if acct == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Unauthenticated, "Unable to authenticate.")
	}

	u, err := iamRepo.LookupUserWithLogin(ctx, acct.GetPublicId(), iam.WithAutoVivify(true))
	if err != nil {
		return nil, err
	}
	tok, err := atRepo.CreateAuthToken(ctx, u, acct.GetPublicId())
	if err != nil {
		return nil, err
	}

	token, err := authtoken.EncryptToken(ctx, s.kms, scopeId, tok.GetPublicId(), tok.GetToken())
	if err != nil {
		return nil, err
	}

	tok.Token = tok.GetPublicId() + "_" + token
	prot := toAuthTokenProto(tok)

	scp, err := iamRepo.LookupScope(ctx, u.GetScopeId())
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

func toAuthMethodProto(in auth.AuthMethod) (*pb.AuthMethod, error) {
	out := &pb.AuthMethod{
		Id:          in.GetPublicId(),
		ScopeId:     in.GetScopeId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
		Version:     in.GetVersion(),
	}
	if in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
	}
	switch i := in.(type) {
	case *password.AuthMethod:
		out.Type = auth.PasswordSubtype.String()
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
		attrs := &pb.OidcAuthMethodAttributes{
			DiscoveryUrl:        wrapperspb.String(i.DiscoveryUrl),
			ClientId:            wrapperspb.String(i.GetClientId()),
			ClientSecretHmac:    i.ClientSecretHmac,
			Certificates:        i.GetCertificates(),
			State:               i.GetOperationalState(),
			SigningAlgorithms:   i.GetSigningAlgs(),
			Audiences:           i.GetAudClaims(),
			CallbackUrlPrefixes: i.GetCallbackUrls(),
		}
		if i.GetMaxAge() != 0 {
			attrs.MaxAge = wrapperspb.Int32(i.GetMaxAge())
		}
		for _, f := range i.GetCallbackUrls() {
			attrs.CallbackUrls = append(attrs.CallbackUrls,
				fmt.Sprintf("%s/v1/auth-methods/%s:authenticate:callback", f, i.GetPublicId()))
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
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, password.AuthMethodPrefix, oidc.AuthMethodPrefix)
}

func validateCreateRequest(req *pbs.CreateAuthMethodRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(req.GetItem().GetScopeId(), scope.Org.Prefix()) &&
			scope.Global.String() != req.GetItem().GetScopeId() {
			badFields["scope_id"] = "This field must be 'global' or a valid org scope id."
		}
		switch auth.SubtypeFromType(req.GetItem().GetType()) {
		case auth.PasswordSubtype:
			attrs := &pb.PasswordAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
		case auth.OidcSubtype:
			attrs := &pb.OidcAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
			if attrs.GetDiscoveryUrl().GetValue() == "" {
				badFields["attributes.discovery_url"] = "Field required for creating an OIDC auth method."
			} else {
				du, err := url.Parse(attrs.GetDiscoveryUrl().GetValue())
				if err != nil {
					badFields["attributes.discovery_url"] = fmt.Sprintf("Cannot be parsed as a url. %v", err)
				}
				if trimmed := strings.TrimSuffix(strings.TrimSuffix(du.RawPath, "/"), "/.well-known/openid-configuration"); trimmed != "" {
					badFields["attributes.discovery_url"] = "The path should be empty or `/.well-known/openid-configuration`"
				}
			}
			if attrs.GetClientId().GetValue() == "" {
				badFields["attributes.client_id"] = "Field required for creating an OIDC auth method."
			}
			if attrs.GetClientSecret().GetValue() == "" {
				badFields["attributes.client_secret"] = "Field required for creating an OIDC auth method."
			}
			if attrs.GetClientSecretHmac() != "" {
				badFields["attributes.client_secret_hmac"] = "Field is read only."
			}
			if attrs.GetState() != "" {
				badFields["attributes.state"] = "Field is read only."
			}
			if len(attrs.GetCallbackUrls()) > 0 {
				badFields["attributes.callback_urls"] = "Field is read only."
			}

			if attrs.GetMaxAge() != nil && attrs.GetMaxAge().GetValue() == 0 {
				badFields["attributes.max_age"] = "If defined, must not be `0`."
			}
			if len(attrs.GetSigningAlgorithms()) > 0 {
				for _, sa := range attrs.GetSigningAlgorithms() {
					if !oidc.SupportedAlgorithm(oidc.Alg(sa)) {
						badFields["attributes.signing_algorithms"] = fmt.Sprintf("Contains unsupported algorithm %q", sa)
						break
					}
				}
			}
			for i, cbUrl := range attrs.GetCallbackUrlPrefixes() {
				if cu, err := url.Parse(cbUrl); err != nil || (cu.Scheme != "http" && cu.Scheme != "https") || cu.Host == "" {
					badFields["attributes.callback_url_prefixes"] = fmt.Sprintf("Value #%d: %q cannot be parsed as a url.", i, cbUrl)
					break
				}
			}
			if len(attrs.GetCertificates()) > 0 {
				if _, err := oidc.ParseCertificates(attrs.GetCertificates()...); err != nil {
					badFields["attributes.certificates"] = fmt.Sprintf("Cannot parse certificates. %v", err.Error())
				}
			}
		default:
			badFields["type"] = fmt.Sprintf("This is a required field and must be %q.", auth.PasswordSubtype.String())
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateAuthMethodRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch auth.SubtypeFromId(req.GetId()) {
		case auth.PasswordSubtype:
			if req.GetItem().GetType() != "" && auth.SubtypeFromType(req.GetItem().GetType()) != auth.PasswordSubtype {
				badFields["type"] = "Cannot modify the resource type."
			}
			pwAttrs := &pb.PasswordAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), pwAttrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
		case auth.OidcSubtype:
			badFields["id"] = "Updating OIDC is not yet support."
		default:
			badFields["id"] = "Incorrectly formatted identifier."
		}
		return badFields
	}, password.AuthMethodPrefix)
}

func validateDeleteRequest(req *pbs.DeleteAuthMethodRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, password.AuthMethodPrefix, oidc.AuthMethodPrefix)
}

func validateListRequest(req *pbs.ListAuthMethodsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(req.GetScopeId(), scope.Org.Prefix()) &&
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

// Deprecated; remove when Authenticate is removedLogin
func validateAuthenticateRequest(req *pbs.AuthenticateRequest) error {
	if st := auth.SubtypeFromId(req.GetAuthMethodId()); st != auth.PasswordSubtype {
		handlers.NotFoundErrorf("This endpoint is not available for the %q Auth Method type.", st.String())
	}
	badFields := make(map[string]string)
	if strings.TrimSpace(req.GetAuthMethodId()) == "" {
		badFields["auth_method_id"] = "This is a required field."
	} else if !handlers.ValidId(req.GetAuthMethodId(), password.AuthMethodPrefix) {
		badFields["auth_method_id"] = "Invalid formatted identifier."
	}
	// TODO: Update this when we enable different auth method types.
	if req.GetCredentials() == nil {
		badFields["credentials"] = "This is a required field."
	}
	creds := req.GetCredentials().GetFields()
	if _, ok := creds[loginNameKey]; !ok {
		badFields["credentials.login_name"] = "This is a required field."
	}
	if _, ok := creds[pwKey]; !ok {
		badFields["credentials.password"] = "This is a required field."
	}
	tType := strings.ToLower(strings.TrimSpace(req.GetTokenType()))
	if tType != "" && tType != "token" && tType != "cookie" {
		badFields["token_type"] = `The only accepted types are "token" and "cookie".`
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid fields provided in request.", badFields)
	}
	return nil
}

func validateAuthenticateLoginRequest(req *pbs.AuthenticateLoginRequest) error {
	if st := auth.SubtypeFromId(req.GetAuthMethodId()); st != auth.PasswordSubtype {
		handlers.NotFoundErrorf("This endpoint is not available for the %q Auth Method type.", st.String())
	}
	badFields := make(map[string]string)
	if strings.TrimSpace(req.GetAuthMethodId()) == "" {
		badFields["auth_method_id"] = "This is a required field."
	} else if !handlers.ValidId(req.GetAuthMethodId(), password.AuthMethodPrefix) {
		badFields["auth_method_id"] = "Invalid formatted identifier."
	}
	if req.GetCredentials() == nil {
		badFields["credentials"] = "This is a required field."
	}
	creds := req.GetCredentials().GetFields()
	if _, ok := creds[loginNameKey]; !ok {
		badFields["credentials.login_name"] = "This is a required field."
	}
	if _, ok := creds[pwKey]; !ok {
		badFields["credentials.password"] = "This is a required field."
	}
	tType := strings.ToLower(strings.TrimSpace(req.GetTokenType()))
	if tType != "" && tType != "token" && tType != "cookie" {
		badFields["token_type"] = `The only accepted types are "token" and "cookie".`
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid fields provided in request.", badFields)
	}
	return nil
}
