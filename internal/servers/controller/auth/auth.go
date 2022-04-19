package auth

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api/recovery"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/gen/controller/tokens"

	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

type TokenFormat uint32

const (
	// We weren't given one or couldn't parse it
	AuthTokenTypeUnknown TokenFormat = iota

	// Came in via the Authentication: Bearer header
	AuthTokenTypeBearer

	// Came in via split cookies
	AuthTokenTypeSplitCookie

	// It's of recovery type
	AuthTokenTypeRecoveryKms
)

const (
	AnonymousUserId = "u_anon"
)

type key int

var verifierKey key

type VerifyResults struct {
	UserId      string
	AuthTokenId string
	Error       error
	Scope       *scopes.ScopeInfo

	// AuthenticatedFinished means that the request has passed through the
	// authentication system successfully. This does _not_ indicate whether a
	// token was provided on the request. Requests for `u_anon` will still have
	// this set true! This is because if a request has a token that is invalid,
	// we fall back to `u_anon` because the request may still be allowed for any
	// anonymous user; it simply fails to validate for and look up grants for an
	// actual known user.
	//
	// A good example is when running dev mode twice. The first time you can
	// authenticate and get a token which is saved by the token helper. The
	// second time, you run a command and it reads the token from the helper.
	// That token is no longer valid, but if the action is granted to `u_anon`
	// the action should still succeed. What happens internally is that the
	// token fails to look up a non-anonymous user, so we fallback to the
	// anonymous user, which is the default.
	//
	// If you want to know if the request had a valid token provided, use a
	// switch on UserId. Anything that isn't `u_anon` will have to have had a
	// valid token provided. And a valid token will never fall back to `u_anon`.
	AuthenticationFinished bool

	// RoundTripValue can be set to allow the function performing authentication
	// (often accompanied by lookup(s)) to return a result of that lookup to the
	// calling function. It is opaque to this package.
	RoundTripValue interface{}

	// Used for additional verification
	v *verifier
}

type verifier struct {
	iamRepoFn       common.IamRepoFactory
	authTokenRepoFn common.AuthTokenRepoFactory
	serversRepoFn   common.ServersRepoFactory
	kms             *kms.Kms
	requestInfo     *authpb.RequestInfo
	res             *perms.Resource
	act             action.Type
	ctx             context.Context
	acl             perms.ACL
}

// NewVerifierContext creates a context that carries a verifier object from the
// HTTP handlers to the gRPC service handlers. It should only be created in the
// HTTP handler and should exist for every request that reaches the service
// handlers.
func NewVerifierContext(ctx context.Context,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	kms *kms.Kms,
	requestInfo *authpb.RequestInfo,
) context.Context {
	return context.WithValue(ctx, verifierKey, &verifier{
		iamRepoFn:       iamRepoFn,
		authTokenRepoFn: authTokenRepoFn,
		serversRepoFn:   serversRepoFn,
		kms:             kms,
		requestInfo:     requestInfo,
	})
}

// Verify takes in a context that has expected parameters as values and runs an
// authn/authz check. It returns a user ID, the scope ID for the request (which
// may come from the URL and may come from the token) and whether or not to
// proceed, e.g. whether the authn/authz check resulted in failure. If an error
// occurs it's logged to the system log.
func Verify(ctx context.Context, opt ...Option) (ret VerifyResults) {
	const op = "auth.Verify"
	ret.Error = handlers.ForbiddenError()
	v, ok := ctx.Value(verifierKey).(*verifier)
	if !ok {
		// We don't have a logger yet and this should never happen in any
		// context we won't catch in tests
		panic("no verifier information found in context")
	}

	ret.v = v

	v.ctx = ctx

	ea := &event.Auth{}
	defer event.WriteAudit(ctx, op, event.WithAuth(ea))

	opts := getOpts(opt...)

	ret.Scope = new(scopes.ScopeInfo)

	// Note: we don't call RequestContextFromCtx here because that performs a
	// SelfOrDefault. That's useful in the handlers, but here we don't want to
	// do anything if it's nil. That's mainly useful in tests where
	// DisableAuthEntirely is set. Later, if we don't have the value set at all,
	// we have some safeguards to ensure we fail safe (e.g. no output fields at
	// all). So it provides a good indication as well whether we have set this
	// where and when needed.
	var reqInfo *requests.RequestContext
	reqInfoRaw := ctx.Value(requests.ContextRequestInformationKey)
	if reqInfoRaw != nil {
		reqInfo = reqInfoRaw.(*requests.RequestContext)
	}

	// In tests we often simply disable auth so we can test the service handlers
	// without fuss
	if v.requestInfo.DisableAuthEntirely {
		yes := true
		ea.DisabledAuthEntirely = &yes
		const op = "auth.(disabled).lookupScope"
		ret.Scope.Id = v.requestInfo.ScopeIdOverride
		if ret.Scope.Id == "" {
			ret.Scope.Id = opts.withScopeId
		}
		// Look up scope details to return. We can skip a lookup when using the
		// global scope
		switch ret.Scope.Id {
		case scope.Global.String():
			ret.Scope = &scopes.ScopeInfo{
				Id:            scope.Global.String(),
				Type:          scope.Global.String(),
				Name:          scope.Global.String(),
				Description:   "Global Scope",
				ParentScopeId: "",
			}

		default:
			iamRepo, err := v.iamRepoFn()
			if err != nil {
				ret.Error = errors.Wrap(ctx, err, op, errors.WithMsg("failed to get iam repo"))
				return
			}

			scp, err := iamRepo.LookupScope(v.ctx, ret.Scope.Id)
			if err != nil {
				ret.Error = errors.Wrap(ctx, err, op)
				return
			}
			if scp == nil {
				ret.Error = errors.New(ctx, errors.InvalidParameter, op, fmt.Sprint("non-existent scope $q", ret.Scope.Id))
				return
			}
			ret.Scope = &scopes.ScopeInfo{
				Id:            scp.GetPublicId(),
				Type:          scp.GetType(),
				Name:          scp.GetName(),
				Description:   scp.GetDescription(),
				ParentScopeId: scp.GetParentId(),
			}
		}
		ret.UserId = v.requestInfo.UserIdOverride
		if reqInfo != nil {
			reqInfo.UserId = ret.UserId
		}
		ea.UserInfo = &event.UserInfo{UserId: ret.UserId}
		ret.Error = nil
		return
	}

	v.act = opts.withAction
	v.res = &perms.Resource{
		ScopeId: opts.withScopeId,
		Id:      opts.withId,
		Pin:     opts.withPin,
		Type:    opts.withType,
	}
	// Global scope has no parent ID; account for this
	if opts.withId == scope.Global.String() && opts.withType == resource.Scope {
		v.res.ScopeId = scope.Global.String()
	}

	if v.requestInfo.EncryptedToken != "" {
		v.decryptToken(ctx)
	}

	var authResults perms.ACLResults
	var grantTuples []perms.GrantTuple
	var accountId, userName, userEmail string
	var err error
	authResults, ret.UserId, accountId, userName, userEmail, ret.Scope, v.acl, grantTuples, err = v.performAuthCheck(ctx)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error performing authn/authz check"))
		return
	}

	ret.AuthTokenId = v.requestInfo.PublicId
	ret.AuthenticationFinished = authResults.AuthenticationFinished
	if !authResults.Authorized {
		if v.requestInfo.DisableAuthzFailures {
			ret.Error = nil
			// TODO: Decide whether to remove this
			err := event.WriteObservation(ctx, op,
				event.WithHeader(
					"auth-results", struct {
						Msg      string          `json:"msg"`
						Resource *perms.Resource `json:"resource"`
						UserId   string          `json:"user_id"`
						Action   string          `json:"action"`
					}{
						Msg:      "failed authz info for request",
						Resource: v.res,
						UserId:   ret.UserId,
						Action:   v.act.String(),
					}))
			if err != nil {
				event.WriteError(ctx, op, err)
			}
		} else {
			// If the anon user was used (either no token, or invalid (perhaps
			// expired) token), return a 401. That way if it's an authn'd user
			// that is not authz'd we'll return 403 to be explicit.
			if ret.UserId == AnonymousUserId {
				ret.Error = handlers.UnauthenticatedError()
			}
			ea.UserInfo = &event.UserInfo{
				UserId: ret.UserId,
			}
			return
		}
	}

	grants := make([]event.Grant, 0, len(grantTuples))
	for _, g := range grantTuples {
		grants = append(grants, event.Grant{
			Grant:   g.Grant,
			RoleId:  g.RoleId,
			ScopeId: g.ScopeId,
		})
	}
	ea.UserInfo = &event.UserInfo{
		UserId:        ret.UserId,
		AuthAccountId: accountId,
	}
	ea.GrantsInfo = &event.GrantsInfo{
		Grants: grants,
	}
	ea.UserName = userName
	ea.UserEmail = userEmail

	if reqInfo != nil {
		reqInfo.UserId = ret.UserId
		reqInfo.OutputFields = authResults.OutputFields
	}

	ret.Error = nil
	return
}

func (v *verifier) decryptToken(ctx context.Context) {
	const op = "auth.(verifier).decryptToken"
	switch v.requestInfo.TokenFormat {
	case uint32(AuthTokenTypeUnknown):
		// Nothing to decrypt
		return

	case uint32(AuthTokenTypeBearer), uint32(AuthTokenTypeSplitCookie):
		if v.kms == nil {
			event.WriteError(ctx, op, stderrors.New("no KMS object available to authz system"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}

		tokenRepo, err := v.authTokenRepoFn()
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("failed to get authtoken repo"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}

		at, err := tokenRepo.LookupAuthToken(v.ctx, v.requestInfo.PublicId)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("failed to look up auth token by public ID"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}
		if at == nil {
			event.WriteError(ctx, op, stderrors.New("nil result from looking up auth token by public ID"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}

		tokenWrapper, err := v.kms.GetWrapper(v.ctx, at.GetScopeId(), kms.KeyPurposeTokens)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to get wrapper for tokens; continuing as anonymous user"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}

		version := v.requestInfo.EncryptedToken[0:len(globals.ServiceTokenV1)]
		switch version {
		case globals.ServiceTokenV1:
		default:
			event.WriteError(ctx, op, stderrors.New("unknown token encryption version; continuing as anonymous user"), event.WithInfo("version", version))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}
		marshaledToken, err := base58.FastBase58Decoding(v.requestInfo.EncryptedToken[len(globals.ServiceTokenV1):])
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error unmarshaling base58 token; continuing as anonymous user"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}

		blobInfo := new(wrapping.BlobInfo)
		if err := proto.Unmarshal(marshaledToken, blobInfo); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error decoding encrypted token; continuing as anonymous user"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}

		s1Bytes, err := tokenWrapper.Decrypt(v.ctx, blobInfo, wrapping.WithAad([]byte(v.requestInfo.PublicId)))
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error decrypting encrypted token; continuing as anonymous user"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}

		var s1Info tokens.S1TokenInfo
		if err := proto.Unmarshal(s1Bytes, &s1Info); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error unmarshaling token info; continuing as anonymous user"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}

		if v.requestInfo.TokenFormat == uint32(AuthTokenTypeUnknown) || s1Info.Token == "" || v.requestInfo.PublicId == "" {
			event.WriteError(ctx, op, stderrors.New("after parsing, could not find valid token; continuing as anonymous user"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}

		v.requestInfo.Token = s1Info.Token
		return

	case uint32(AuthTokenTypeRecoveryKms):
		if v.kms == nil {
			event.WriteError(ctx, op, stderrors.New("no KMS object available to authz system"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}
		wrapper := v.kms.GetExternalWrappers().Recovery()
		if wrapper == nil {
			event.WriteError(ctx, op, stderrors.New("no recovery KMS is available"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}
		info, err := recovery.ParseRecoveryToken(v.ctx, wrapper, v.requestInfo.EncryptedToken)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("decrypt recovery token: error parsing and validating recovery token"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}
		// If we add the validity period to the creation time (which we've
		// verified is before the current time, with a minute of fudging), and
		// it's before now, it's expired and might be a replay.
		if info.CreationTime.Add(globals.RecoveryTokenValidityPeriod).Before(time.Now()) {
			event.WriteError(ctx, op, stderrors.New("recovery token has expired (possible replay attack)"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}
		repo, err := v.serversRepoFn()
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("decrypt recovery token: error fetching servers repo"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}
		if err := repo.AddNonce(v.ctx, info.Nonce, servers.NoncePurposeRecovery); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("decrypt recovery token: error adding nonce to database (possible replay attack)"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}
		event.WriteError(ctx, op, stderrors.New("recovery KMS was used to authorize a call"), event.WithInfo("url", v.requestInfo.Path, "method", v.requestInfo.Method))
	}
}

func (v verifier) performAuthCheck(ctx context.Context) (
	aclResults perms.ACLResults,
	userId string,
	accountId string,
	userName string,
	userEmail string,
	scopeInfo *scopes.ScopeInfo,
	retAcl perms.ACL,
	grantTuples []perms.GrantTuple,
	retErr error,
) {
	const op = "auth.(verifier).performAuthCheck"
	// Ensure we return an error by default if we forget to set this somewhere
	retErr = errors.New(ctx, errors.Unknown, op, "default auth error", errors.WithoutEvent())
	// Make the linter happy
	_ = retErr
	scopeInfo = new(scopes.ScopeInfo)
	userId = AnonymousUserId

	// Validate the token and fetch the corresponding user ID
	switch v.requestInfo.TokenFormat {
	case uint32(AuthTokenTypeUnknown):
		// Nothing; remain as the anonymous user

	case uint32(AuthTokenTypeRecoveryKms):
		// We validated the encrypted token in decryptToken and handled the
		// nonces there, so just set the user
		userId = "u_recovery"

	case uint32(AuthTokenTypeBearer), uint32(AuthTokenTypeSplitCookie):
		if v.requestInfo.Token == "" {
			// This will end up staying as the anonymous user
			break
		}
		tokenRepo, err := v.authTokenRepoFn()
		if err != nil {
			retErr = errors.Wrap(ctx, err, op)
			return
		}
		at, err := tokenRepo.ValidateToken(v.ctx, v.requestInfo.PublicId, v.requestInfo.Token)
		if err != nil {
			// Continue as the anonymous user as maybe this token is expired but
			// we can still perform the action
			event.WriteError(ctx, op, err, event.WithInfoMsg("error validating token; continuing as anonymous user"))
			break
		}
		if at != nil {
			accountId = at.GetAuthAccountId()
			userId = at.GetIamUserId()
			if userId == "" {
				event.WriteError(ctx, op, stderrors.New("perform auth check: valid token did not map to a user, likely because no account is associated with the user any longer; continuing as u_anon"), event.WithInfo("token_id", at.GetPublicId()))
				userId = AnonymousUserId
				accountId = ""
			}
		}
	}

	iamRepo, err := v.iamRepoFn()
	if err != nil {
		retErr = errors.Wrap(ctx, err, op, errors.WithMsg("failed to get iam repo"))
		return
	}

	u, _, err := iamRepo.LookupUser(ctx, userId)
	if err != nil {
		retErr = errors.Wrap(ctx, err, op, errors.WithMsg("failed to lookup user"))
		return
	}
	userEmail = u.Email
	userName = u.FullName

	// Look up scope details to return. We can skip a lookup when using the
	// global scope
	switch v.res.ScopeId {
	case scope.Global.String():
		scopeInfo = &scopes.ScopeInfo{
			Id:            scope.Global.String(),
			Type:          scope.Global.String(),
			Name:          scope.Global.String(),
			Description:   "Global Scope",
			ParentScopeId: "",
		}

	default:
		scp, err := iamRepo.LookupScope(v.ctx, v.res.ScopeId)
		if err != nil {
			retErr = errors.Wrap(ctx, err, op)
			return
		}
		if scp == nil {
			retErr = errors.New(ctx, errors.InvalidParameter, op, fmt.Sprint("non-existent scope $q", v.res.ScopeId))
			return
		}
		scopeInfo = &scopes.ScopeInfo{
			Id:            scp.GetPublicId(),
			Type:          scp.GetType(),
			Name:          scp.GetName(),
			Description:   scp.GetDescription(),
			ParentScopeId: scp.GetParentId(),
		}
	}

	// At this point we don't need to look up grants since it's automatically allowed
	if v.requestInfo.TokenFormat == uint32(AuthTokenTypeRecoveryKms) {
		aclResults.AuthenticationFinished = true
		aclResults.Authorized = true
		retErr = nil
		return
	}

	var parsedGrants []perms.Grant

	// Fetch and parse grants for this user ID (which may include grants for
	// u_anon and u_auth)
	grantTuples, err = iamRepo.GrantsForUser(v.ctx, userId)
	if err != nil {
		retErr = errors.Wrap(ctx, err, op)
		return
	}
	parsedGrants = make([]perms.Grant, 0, len(grantTuples))
	// Note: Below, we always skip validation so that we don't error on formats
	// that we've since restricted, e.g. "id=foo;actions=create,read". These
	// will simply not have an effect.
	for _, pair := range grantTuples {
		parsed, err := perms.Parse(
			pair.ScopeId,
			pair.Grant,
			perms.WithUserId(userId),
			perms.WithAccountId(accountId),
			perms.WithSkipFinalValidation(true))
		if err != nil {
			retErr = errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed to parse grant %#v", pair.Grant)))
			return
		}
		parsedGrants = append(parsedGrants, parsed)
	}

	retAcl = perms.NewACL(parsedGrants...)
	aclResults = retAcl.Allowed(*v.res, v.act)
	// We don't set authenticated above because setting this but not authorized
	// is used for further permissions checks, such as during recursive listing.
	// So we want to make sure any code relying on that has the full set of
	// grants successfully loaded.
	aclResults.AuthenticationFinished = true
	retErr = nil
	return
}

// FetchActionSetForId returns the allowed actions for a given ID using the
// current set of ACLs and all other parameters the same (user, etc.)
func (r *VerifyResults) FetchActionSetForId(ctx context.Context, id string, availableActions action.ActionSet, opt ...Option) action.ActionSet {
	return r.fetchActions(id, resource.Unknown, availableActions, opt...)
}

// FetchActionSetForType returns the allowed actions for a given collection type
// using the current set of ACLs and all other parameters the same (user, etc.)
func (r *VerifyResults) FetchActionSetForType(ctx context.Context, typ resource.Type, availableActions action.ActionSet, opt ...Option) action.ActionSet {
	return r.fetchActions("", typ, availableActions, opt...)
}

func (r *VerifyResults) fetchActions(id string, typ resource.Type, availableActions action.ActionSet, opt ...Option) action.ActionSet {
	switch {
	case r.v.requestInfo.DisableAuthEntirely,
		r.v.requestInfo.TokenFormat == uint32(AuthTokenTypeRecoveryKms):
		// TODO: See if we can be better about what we return with the anonymous
		// user and recovery KMS, perhaps given exclusionary options for each
		return availableActions
	}

	opts := getOpts(opt...)
	res := opts.withResource
	// If not passed in, use what's already been populated through verification
	if res == nil {
		res = r.v.res
	}
	// If this is being called directly we may not have a resource yet
	if res == nil {
		res = new(perms.Resource)
	}
	if id != "" {
		res.Id = id
	}
	if typ != resource.Unknown {
		res.Type = typ
	}

	ret := make(action.ActionSet, 0, len(availableActions))
	for _, act := range availableActions {
		if r.v.acl.Allowed(*res, act).Authorized {
			ret = append(ret, act)
		}
	}
	if len(ret) == 0 {
		return nil
	}
	return ret
}

func (r *VerifyResults) FetchOutputFields(res perms.Resource, act action.Type) perms.OutputFieldsMap {
	switch {
	case r.v.requestInfo.TokenFormat == uint32(AuthTokenTypeRecoveryKms):
		return perms.OutputFieldsMap{"*": true}
	case r.v.requestInfo.DisableAuthEntirely:
		return nil
	}

	return r.v.acl.Allowed(res, act).OutputFields
}

// GetTokenFromRequest pulls the token from either the Authorization header or
// split cookies and parses it. If it cannot be parsed successfully, the issue
// is logged and we return blank, so logic will continue as the anonymous user.
// The public ID and _encrypted_ token are returned along with the token format.
func GetTokenFromRequest(ctx context.Context, kmsCache *kms.Kms, req *http.Request) (string, string, uint32) {
	const op = "auth.GetTokenFromRequest"
	// First, get the token, either from the authorization header or from split
	// cookies
	var receivedTokenType TokenFormat
	var fullToken string
	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		headerSplit := strings.SplitN(strings.TrimSpace(authHeader), " ", 2)
		if len(headerSplit) == 2 && strings.EqualFold(strings.TrimSpace(headerSplit[0]), "bearer") {
			receivedTokenType = AuthTokenTypeBearer
			fullToken = strings.TrimSpace(headerSplit[1])
		}
	}
	if receivedTokenType != AuthTokenTypeBearer {
		var httpCookiePayload string
		var jsCookiePayload string
		if hc, err := req.Cookie(handlers.HttpOnlyCookieName); err == nil {
			httpCookiePayload = hc.Value
		}
		if jc, err := req.Cookie(handlers.JsVisibleCookieName); err == nil {
			jsCookiePayload = jc.Value
		}
		if httpCookiePayload != "" && jsCookiePayload != "" {
			receivedTokenType = AuthTokenTypeSplitCookie
			fullToken = jsCookiePayload + httpCookiePayload
		}
	}

	if receivedTokenType == AuthTokenTypeUnknown || fullToken == "" {
		// We didn't find auth info or a client screwed up and put in a blank
		// header instead of nothing at all, so return blank which will indicate
		// the anonymouse user
		return "", "", uint32(AuthTokenTypeUnknown)
	}

	if strings.HasPrefix(fullToken, "r_") {
		return "", fullToken, uint32(AuthTokenTypeRecoveryKms)
	}

	splitFullToken := strings.Split(fullToken, "_")
	if len(splitFullToken) != 3 {
		event.WriteError(ctx, op, stderrors.New("unexpected number of segments in token; continuing as anonymous user"), event.WithInfo("expected", 3, "found", len(splitFullToken)))
		return "", "", uint32(AuthTokenTypeUnknown)
	}

	publicId := strings.Join(splitFullToken[0:2], "_")
	encryptedToken := splitFullToken[2]

	return publicId, encryptedToken, uint32(receivedTokenType)
}
