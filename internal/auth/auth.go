package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/internal/gen/controller/tokens"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/recovery"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/kr/pretty"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

type TokenFormat int

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

type key int

var verifierKey key

// RequestInfo contains request parameters necessary for checking authn/authz
type RequestInfo struct {
	Path           string
	Method         string
	PublicId       string
	EncryptedToken string
	Token          string
	TokenFormat    TokenFormat

	// The following are useful for tests
	scopeIdOverride      string
	userIdOverride       string
	DisableAuthzFailures bool
	DisableAuthEntirely  bool
}

type VerifyResults struct {
	UserId      string
	AuthTokenId string
	Error       error
	Scope       *scopes.ScopeInfo

	// RoundTripValue can be set to allow the function performing authentication
	// (often accompanied by lookup(s)) to return a result of that lookup to the
	// calling function. It is opaque to this package.
	RoundTripValue interface{}

	// Used for additional verification
	v *verifier
}

type verifier struct {
	logger          hclog.Logger
	iamRepoFn       common.IamRepoFactory
	authTokenRepoFn common.AuthTokenRepoFactory
	serversRepoFn   common.ServersRepoFactory
	kms             *kms.Kms
	requestInfo     RequestInfo
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
	logger hclog.Logger,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	kms *kms.Kms,
	requestInfo RequestInfo) context.Context {
	return context.WithValue(ctx, verifierKey, &verifier{
		logger:          logger,
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
	ret.Error = handlers.ForbiddenError()
	v, ok := ctx.Value(verifierKey).(*verifier)
	if !ok {
		// We don't have a logger yet and this should never happen in any
		// context we won't catch in tests
		panic("no verifier information found in context")
	}

	ret.v = v

	v.ctx = ctx

	opts := getOpts(opt...)

	ret.Scope = new(scopes.ScopeInfo)
	if v.requestInfo.DisableAuthEntirely {
		ret.Scope.Id = v.requestInfo.scopeIdOverride
		if ret.Scope.Id == "" {
			ret.Scope.Id = opts.withScopeId
		}
		switch {
		case ret.Scope.Id == "global":
			ret.Scope.Type = "global"
		case strings.HasPrefix(ret.Scope.Id, scope.Org.Prefix()):
			ret.Scope.Type = scope.Org.String()
		case strings.HasPrefix(ret.Scope.Id, scope.Project.Prefix()):
			ret.Scope.Type = scope.Project.String()
		}
		ret.UserId = v.requestInfo.userIdOverride
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
		v.decryptToken()
	}

	var authResults perms.ACLResults
	var err error
	authResults, ret.UserId, ret.Scope, v.acl, err = v.performAuthCheck()
	if err != nil {
		v.logger.Error("error performing authn/authz check", "error", err)
		return
	}

	ret.AuthTokenId = v.requestInfo.PublicId
	if !authResults.Allowed {
		if v.requestInfo.DisableAuthzFailures {
			ret.Error = nil
			// TODO: Decide whether to remove this
			v.logger.Info("failed authz info for request", "resource", pretty.Sprint(v.res), "user_id", ret.UserId, "action", v.act.String())
		} else {
			// If the anon user was used (either no token, or invalid (perhaps
			// expired) token), return a 401. That way if it's an authn'd user
			// that is not authz'd we'll return 403 to be explicit.
			if ret.UserId == "u_anon" {
				ret.Error = handlers.UnauthenticatedError()
			}
			return
		}
	}

	ret.Error = nil
	return
}

func (v *verifier) decryptToken() {
	switch v.requestInfo.TokenFormat {
	case AuthTokenTypeUnknown:
		// Nothing to decrypt
		return

	case AuthTokenTypeBearer, AuthTokenTypeSplitCookie:
		if v.kms == nil {
			v.logger.Trace("decrypt token: no KMS object available to authz system")
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}

		tokenRepo, err := v.authTokenRepoFn()
		if err != nil {
			v.logger.Warn("decrypt bearer token: failed to get authtoken repo", "error", err)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}

		at, err := tokenRepo.LookupAuthToken(v.ctx, v.requestInfo.PublicId)
		if err != nil {
			v.logger.Trace("decrypt bearer token: failed to look up auth token by public ID", "error", err)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}
		if at == nil {
			v.logger.Trace("decrypt bearer token: nil result from looking up auth token by public ID")
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}

		tokenWrapper, err := v.kms.GetWrapper(v.ctx, at.GetScopeId(), kms.KeyPurposeTokens)
		if err != nil {
			v.logger.Warn("decrypt bearer token: unable to get wrapper for tokens; continuing as anonymous user", "error", err)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}

		version := v.requestInfo.EncryptedToken[0:len(globals.ServiceTokenV1)]
		switch version {
		case globals.ServiceTokenV1:
		default:
			v.logger.Trace("decrypt bearer token: unknown token encryption version; continuing as anonymous user", "version", version)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}
		marshaledToken, err := base58.FastBase58Decoding(v.requestInfo.EncryptedToken[len(globals.ServiceTokenV1):])
		if err != nil {
			v.logger.Trace("decrypt bearer token: error unmarshaling base58 token; continuing as anonymous user", "error", err)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}

		blobInfo := new(wrapping.EncryptedBlobInfo)
		if err := proto.Unmarshal(marshaledToken, blobInfo); err != nil {
			v.logger.Trace("decrypt bearer token: error decoding encrypted token; continuing as anonymous user", "error", err)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}

		s1Bytes, err := tokenWrapper.Decrypt(v.ctx, blobInfo, []byte(v.requestInfo.PublicId))
		if err != nil {
			v.logger.Trace("decrypt bearer token: error decrypting encrypted token; continuing as anonymous user", "error", err)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}

		var s1Info tokens.S1TokenInfo
		if err := proto.Unmarshal(s1Bytes, &s1Info); err != nil {
			v.logger.Trace("decrypt bearer token: error unmarshaling token info; continuing as anonymous user", "error", err)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}

		if v.requestInfo.TokenFormat == AuthTokenTypeUnknown || s1Info.Token == "" || v.requestInfo.PublicId == "" {
			v.logger.Trace("decrypt bearer token: after parsing, could not find valid token; continuing as anonymous user")
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}

		v.requestInfo.Token = s1Info.Token
		return

	case AuthTokenTypeRecoveryKms:
		if v.kms == nil {
			v.logger.Trace("decrypt recovery token: no KMS object available to authz system")
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}
		wrapper := v.kms.GetExternalWrappers().Recovery()
		if wrapper == nil {
			v.logger.Trace("decrypt recovery token: no recovery KMS is available")
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}
		info, err := recovery.ParseRecoveryToken(v.ctx, wrapper, v.requestInfo.EncryptedToken)
		if err != nil {
			v.logger.Trace("decrypt recovery token: error parsing and validating recovery token", "error", err)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}
		// If we add the validity period to the creation time (which we've
		// verified is before the current time, with a minute of fudging), and
		// it's before now, it's expired and might be a replay.
		if info.CreationTime.Add(globals.RecoveryTokenValidityPeriod).Before(time.Now()) {
			v.logger.Warn("decrypt recovery token: recovery token has expired (possible replay attack)")
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}
		repo, err := v.serversRepoFn()
		if err != nil {
			v.logger.Trace("decrypt recovery token: error fetching servers repo", "error", err)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}
		if err := repo.AddRecoveryNonce(v.ctx, info.Nonce); err != nil {
			v.logger.Warn("decrypt recovery token: error adding nonce to database (possible replay attack)", "error", err)
			v.requestInfo.TokenFormat = AuthTokenTypeUnknown
			return
		}
		v.logger.Warn("recovery KMS was used to authorize a call", "url", v.requestInfo.Path, "method", v.requestInfo.Method)
	}
}

func (v verifier) performAuthCheck() (aclResults perms.ACLResults, userId string, scopeInfo *scopes.ScopeInfo, retAcl perms.ACL, retErr error) {
	const op = "auth.(verifier).performAuthCheck"
	// Ensure we return an error by default if we forget to set this somewhere
	retErr = errors.New(errors.Unknown, op, "default auth error")
	// Make the linter happy
	_ = retErr
	scopeInfo = new(scopes.ScopeInfo)
	userId = "u_anon"
	var accountId string

	// Validate the token and fetch the corresponding user ID
	switch v.requestInfo.TokenFormat {
	case AuthTokenTypeUnknown:
		// Nothing; remain as the anonymous user

	case AuthTokenTypeRecoveryKms:
		// We validated the encrypted token in decryptToken and handled the
		// nonces there, so just set the user
		userId = "u_recovery"

	case AuthTokenTypeBearer, AuthTokenTypeSplitCookie:
		if v.requestInfo.Token == "" {
			// This will end up staying as the anonymous user
			break
		}
		tokenRepo, err := v.authTokenRepoFn()
		if err != nil {
			retErr = errors.Wrap(err, op)
			return
		}
		at, err := tokenRepo.ValidateToken(v.ctx, v.requestInfo.PublicId, v.requestInfo.Token)
		if err != nil {
			// Continue as the anonymous user as maybe this token is expired but
			// we can still perform the action
			v.logger.Error("perform auth check: error validating token; continuing as anonymous user", "error", err)
			break
		}
		if at != nil {
			accountId = at.GetAuthAccountId()
			userId = at.GetIamUserId()
			if userId == "" {
				v.logger.Warn("perform auth check: valid token did not map to a user, likely because no account is associated with the user any longer; continuing as u_anon", "token_id", at.GetPublicId())
				userId = "u_anon"
				accountId = ""
			}
		}
	}

	iamRepo, err := v.iamRepoFn()
	if err != nil {
		retErr = errors.Wrap(err, op, errors.WithMsg("failed to get iam repo"))
		return
	}

	// Look up scope details to return. We can skip a lookup when using the
	// global scope
	switch v.res.ScopeId {
	case "global":
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
			retErr = errors.Wrap(err, op)
			return
		}
		if scp == nil {
			retErr = errors.New(errors.InvalidParameter, op, fmt.Sprint("non-existent scope $q", v.res.ScopeId))
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
	if v.requestInfo.TokenFormat == AuthTokenTypeRecoveryKms {
		aclResults.Allowed = true
		retErr = nil
		return
	}

	var parsedGrants []perms.Grant
	var grantPairs []perms.GrantPair

	// Fetch and parse grants for this user ID (which may include grants for
	// u_anon and u_auth)
	grantPairs, err = iamRepo.GrantsForUser(v.ctx, userId)
	if err != nil {
		retErr = errors.Wrap(err, op)
		return
	}
	parsedGrants = make([]perms.Grant, 0, len(grantPairs))
	// Note: Below, we always skip validation so that we don't error on formats
	// that we've since restricted, e.g. "id=foo;actions=create,read". These
	// will simply not have an effect.
	for _, pair := range grantPairs {
		parsed, err := perms.Parse(
			pair.ScopeId,
			pair.Grant,
			perms.WithUserId(userId),
			perms.WithAccountId(accountId),
			perms.WithSkipFinalValidation(true))
		if err != nil {
			retErr = errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed to parse grant %#v", pair.Grant)))
			return
		}
		parsedGrants = append(parsedGrants, parsed)
	}

	retAcl = perms.NewACL(parsedGrants...)
	aclResults = retAcl.Allowed(*v.res, v.act)
	retErr = nil
	return
}

// FetchActionSetForId returns the allowed actions for a given ID using the
// current set of ACLs and all other parameters the same (user, etc.)
func (r *VerifyResults) FetchActionSetForId(ctx context.Context, id string, availableActions action.ActionSet, opt ...Option) action.ActionSet {
	return r.fetchActions(ctx, id, resource.Unknown, availableActions, opt...)
}

// FetchActionSetForType returns the allowed actions for a given collection type
// using the current set of ACLs and all other parameters the same (user, etc.)
func (r *VerifyResults) FetchActionSetForType(ctx context.Context, typ resource.Type, availableActions action.ActionSet, opt ...Option) action.ActionSet {
	return r.fetchActions(ctx, "", typ, availableActions, opt...)
}

func (r *VerifyResults) fetchActions(ctx context.Context, id string, typ resource.Type, availableActions action.ActionSet, opt ...Option) action.ActionSet {
	switch {
	case r.v.requestInfo.DisableAuthEntirely,
		r.v.requestInfo.TokenFormat == AuthTokenTypeRecoveryKms:
		// TODO: See if we can be better about what we return with the anonymous
		// user and recovery KMS, perhaps given exclusionary options for each
		return availableActions
	}

	opts := getOpts(opt...)
	res := opts.withResource
	if res == nil {
		res = r.v.res
	}
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
		if r.v.acl.Allowed(*res, act).Allowed {
			ret = append(ret, act)
		}
	}
	if len(ret) == 0 {
		return nil
	}
	return ret
}

// GetTokenFromRequest pulls the token from either the Authorization header or
// split cookies and parses it. If it cannot be parsed successfully, the issue
// is logged and we return blank, so logic will continue as the anonymous user.
// The public ID and _encrypted_ token are returned along with the token format.
func GetTokenFromRequest(logger hclog.Logger, kmsCache *kms.Kms, req *http.Request) (string, string, TokenFormat) {
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
		return "", "", AuthTokenTypeUnknown
	}

	if strings.HasPrefix(fullToken, "r_") {
		return "", fullToken, AuthTokenTypeRecoveryKms
	}

	splitFullToken := strings.Split(fullToken, "_")
	if len(splitFullToken) != 3 {
		logger.Trace("get token from request: unexpected number of segments in token; continuing as anonymous user", "expected", 3, "found", len(splitFullToken))
		return "", "", AuthTokenTypeUnknown
	}

	publicId := strings.Join(splitFullToken[0:2], "_")
	encryptedToken := splitFullToken[2]

	return publicId, encryptedToken, receivedTokenType
}
