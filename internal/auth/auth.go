package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/recovery"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/kr/pretty"
	"google.golang.org/protobuf/proto"
)

type TokenFormat int

const (
	// We weren't given one or couldn't parse it. This is different from when a
	// token is cryptographically invalid, which will be Invalid and always
	// return a 403.
	AuthTokenTypeUnknown TokenFormat = iota

	// Came in via the Authentication: Bearer header
	AuthTokenTypeBearer

	// Came in via split cookies
	AuthTokenTypeSplitCookie

	// It's of recovery type
	AuthTokenTypeRecoveryKms

	// It's _known_ to be invalid, that is, a token was provided that is simply
	// not valid and may be part of a DDoS or other attack
	AuthTokenTypeInvalid
)

type key int

var verifierKey key

// RequestInfo contains request parameters necessary for checking authn/authz
type RequestInfo struct {
	Path        string
	Method      string
	PublicId    string
	Token       string
	TokenFormat TokenFormat

	// These are set by the service handlers via options
	scopeId string
	pin     string

	// This is used by the scopes collection
	userIdOverride string

	// The following are useful for tests
	DisableAuthzFailures bool
	DisableAuthEntirely  bool
}

type VerifyResults struct {
	UserId string
	Error  error
	Scope  *scopes.ScopeInfo
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
	v.ctx = ctx

	opts := getOpts(opt...)

	ret.Scope = new(scopes.ScopeInfo)
	if v.requestInfo.DisableAuthEntirely {
		ret.Scope.Id = v.requestInfo.scopeId
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

	// table stakes
	if v.requestInfo.TokenFormat == AuthTokenTypeInvalid {
		// TODO: Consider moving this forward to the HTTP handler, and just
		// manually marshal the error type. That should allow avoiding some DB
		// lookups, although this would not be a common case.
		v.logger.Trace("got invalid token type in auth function, which should not have occurred")
		return
	}

	v.act = opts.withAction
	v.res = &perms.Resource{
		ScopeId: opts.withScopeId,
		Id:      opts.withId,
		Pin:     opts.withPin,
		Type:    opts.withType,
	}

	var authResults *perms.ACLResults
	var err error
	authResults, ret.UserId, ret.Scope, err = v.performAuthCheck()
	if err != nil {
		v.logger.Error("error performing authn/authz check", "error", err)
		return
	}
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

func (v verifier) performAuthCheck() (aclResults *perms.ACLResults, userId string, scopeInfo *scopes.ScopeInfo, retErr error) {
	// Ensure we return an error by default if we forget to set this somewhere
	retErr = errors.New("unknown")
	// Make the linter happy
	_ = retErr
	scopeInfo = new(scopes.ScopeInfo)
	userId = "u_anon"

	// Validate the token and fetch the corresponding user ID
	switch v.requestInfo.TokenFormat {
	case AuthTokenTypeBearer, AuthTokenTypeSplitCookie:
		if v.requestInfo.Token == "" {
			// This will end up staying as the anonymous user
			break
		}
		tokenRepo, err := v.authTokenRepoFn()
		if err != nil {
			retErr = fmt.Errorf("perform auth check: failed to get authtoken repo: %w", err)
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
			userId = at.GetIamUserId()
		}

	case AuthTokenTypeRecoveryKms:
		userId = "u_recovery"
		if v.kms == nil {
			retErr = errors.New("perform auth check: no KMS object available to authz system")
			return
		}
		wrapper := v.kms.GetExternalWrappers().Recovery()
		if wrapper == nil {
			retErr = errors.New("perform auth check: no recovery KMS is available")
			return
		}
		info, err := recovery.ParseRecoveryToken(v.ctx, wrapper, v.requestInfo.Token)
		if err != nil {
			retErr = fmt.Errorf("perform auth check: error validating recovery token: %w", err)
			return
		}
		// If we add the validity period to the creation time (which we've
		// verified is before the current time, with a minute of fudging), and
		// it's before now, it's expired and might be a replay.
		if info.CreationTime.Add(globals.RecoveryTokenValidityPeriod).Before(time.Now()) {
			retErr = errors.New("WARNING: perform auth check: recovery token has expired (possible replay attack)")
			return
		}
		repo, err := v.serversRepoFn()
		if err != nil {
			retErr = fmt.Errorf("perform auth check: error fetching servers repo: %w", err)
			return
		}
		if err := repo.AddRecoveryNonce(v.ctx, info.Nonce); err != nil {
			retErr = fmt.Errorf("WARNING: perform auth check: error adding nonce to database (possible replay attack): %w", err)
			return
		}
		v.logger.Warn("NOTE: recovery KMS was used to authorize a call", "url", v.requestInfo.Path, "method", v.requestInfo.Method)
	}

	iamRepo, err := v.iamRepoFn()
	if err != nil {
		retErr = fmt.Errorf("perform auth check: failed to get iam repo: %w", err)
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
			retErr = fmt.Errorf("perform auth check: failed to lookup scope: %w", err)
			return
		}
		if scp == nil {
			retErr = fmt.Errorf("perform auth check: non-existent scope %q", v.res.ScopeId)
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
		aclResults = &perms.ACLResults{Allowed: true}
		retErr = nil
		return
	}

	var parsedGrants []perms.Grant
	var grantPairs []perms.GrantPair

	// Fetch and parse grants for this user ID (which may include grants for
	// u_anon and u_auth)
	grantPairs, err = iamRepo.GrantsForUser(v.ctx, userId)
	if err != nil {
		retErr = fmt.Errorf("perform auth check: failed to query for user grants: %w", err)
		return
	}
	parsedGrants = make([]perms.Grant, 0, len(grantPairs))
	for _, pair := range grantPairs {
		parsed, err := perms.Parse(pair.ScopeId, userId, pair.Grant)
		if err != nil {
			retErr = fmt.Errorf("perform auth check: failed to parse grant %#v: %w", pair.Grant, err)
			return
		}
		parsedGrants = append(parsedGrants, parsed)
	}

	acl := perms.NewACL(parsedGrants...)
	allowed := acl.Allowed(*v.res, v.act)

	aclResults = &allowed
	retErr = nil
	return
}

// GetTokenFromRequest pulls the token from either the Authorization header or
// split cookies and parses it. If it cannot be parsed successfully, the issue
// is logged and we return blank, so logic will continue as the anonymous user.
// The public ID and token are returned along with the token format.
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
		logger.Trace("get token from request: unexpected number of segments in token", "expected", 3, "found", len(splitFullToken))
		return "", "", AuthTokenTypeInvalid
	}

	publicId := strings.Join(splitFullToken[0:2], "_")

	// This is hardcoded to global because at this point we don't know the
	// scope. But that's okay; this is not really a security feature so much as
	// an anti-DDoSing-the-backing-database feature.
	tokenWrapper, err := kmsCache.GetWrapper(req.Context(), scope.Global.String(), kms.KeyPurposeTokens)
	if err != nil {
		logger.Warn("get token from request: unable to get wrapper for tokens", "error", err)
		return "", "", AuthTokenTypeInvalid
	}

	version := string(splitFullToken[2][0])
	switch version {
	case globals.TokenEncryptionVersion:
	default:
		logger.Trace("unknown token encryption version", "version", version)
		return "", "", AuthTokenTypeInvalid
	}
	marshaledToken := base58.Decode(splitFullToken[2][1:])

	blobInfo := new(wrapping.EncryptedBlobInfo)
	if err := proto.Unmarshal(marshaledToken, blobInfo); err != nil {
		logger.Trace("error decoding encrypted token", "error", err)
		return "", "", AuthTokenTypeInvalid
	}

	tokenBytes, err := tokenWrapper.Decrypt(req.Context(), blobInfo, []byte(publicId))
	if err != nil {
		logger.Trace("error decrypting encrypted token", "error", err)
		return "", "", AuthTokenTypeInvalid
	}
	token := string(tokenBytes)

	if receivedTokenType == AuthTokenTypeUnknown || token == "" || publicId == "" {
		logger.Trace("get token from request: after parsing, could not find valid token")
		return "", "", AuthTokenTypeInvalid
	}

	return publicId, token, receivedTokenType
}
