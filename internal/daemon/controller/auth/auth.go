// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/gen/controller/tokens"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/internal/util/template"
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

// CallbackAction represents the action type for
// callback operations in a request's URL path.
// This is currently only used during auth method
// authentication.
const CallbackAction = "callback"

type key int

var verifierKey key

type VerifyResults struct {
	UserData template.Data
	// This is copied out from UserData above but used to avoid nil checks in
	// lots of places that embed this value
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
	RoundTripValue any

	// Used for additional verification
	v *verifier

	// Used to generate a hash of all grants
	grants perms.GrantTuples
}

type verifier struct {
	iamRepoFn          common.IamRepoFactory
	authTokenRepoFn    common.AuthTokenRepoFactory
	serversRepoFn      common.ServersRepoFactory
	passwordAuthRepoFn common.PasswordAuthRepoFactory
	oidcAuthRepoFn     common.OidcAuthRepoFactory
	ldapAuthRepoFn     common.LdapAuthRepoFactory
	kms                *kms.Kms
	requestInfo        *authpb.RequestInfo
	res                *perms.Resource
	act                action.Type
	ctx                context.Context
	acl                perms.ACL
}

// TODO (jefferai 10/2022): NewVerifierContextWithAccounts performs the function
// of NewVerifierContext (see the docs for that function) but with extra
// parameters that can be used to look up account information. This is not
// intended to be a long-lived function; see
// https://hashicorp.atlassian.net/browse/ICU-6571 and
// https://hashicorp.atlassian.net/browse/ICU-6572
//
// This is being added for a quick turnaround purpose and to avoid making large
// numbers of changes to tests when we may do a much bigger refactor; when those
// items are addressed this can be removed.
func NewVerifierContextWithAccounts(ctx context.Context,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	passwordAuthRepoFn common.PasswordAuthRepoFactory,
	oidcAuthRepoFn common.OidcAuthRepoFactory,
	ldapAuthRepoFn common.LdapAuthRepoFactory,
	kms *kms.Kms,
	requestInfo *authpb.RequestInfo,
) context.Context {
	return context.WithValue(ctx, verifierKey, &verifier{
		iamRepoFn:          iamRepoFn,
		authTokenRepoFn:    authTokenRepoFn,
		serversRepoFn:      serversRepoFn,
		passwordAuthRepoFn: passwordAuthRepoFn,
		oidcAuthRepoFn:     oidcAuthRepoFn,
		ldapAuthRepoFn:     ldapAuthRepoFn,
		kms:                kms,
		requestInfo:        requestInfo,
	})
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
	return NewVerifierContextWithAccounts(ctx, iamRepoFn, authTokenRepoFn, serversRepoFn, nil, nil, nil, kms, requestInfo)
}

// Verify takes in a context that has expected parameters as values and runs an
// authn/authz check. It returns a user ID, the scope ID for the request (which
// may come from the URL and may come from the token) and whether or not to
// proceed, e.g. whether the authn/authz check resulted in failure. If an error
// occurs it's logged to the system log.
func Verify(ctx context.Context, resourceType resource.Type, opt ...Option) (ret VerifyResults) {
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
	defer func() {
		if err := event.WriteAudit(ctx, op, event.WithAuth(ea)); err != nil {
			event.WriteError(ctx, op, err)
		}
	}()

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
				return ret
			}

			scp, err := iamRepo.LookupScope(v.ctx, ret.Scope.Id)
			if err != nil {
				ret.Error = errors.Wrap(ctx, err, op)
				return ret
			}
			if scp == nil {
				ret.Error = errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("non-existent scope %q", ret.Scope.Id))
				return ret
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
		ret.UserData.User.Id = util.Pointer(ret.UserId)
		if reqInfo != nil {
			reqInfo.UserId = ret.UserId
		}
		ea.UserInfo = &event.UserInfo{UserId: ret.UserId}
		ret.Error = nil
		return ret
	}

	v.act = opts.withAction
	v.res = &perms.Resource{
		ScopeId: opts.withScopeId,
		Id:      opts.withId,
		Pin:     opts.withPin,
		Type:    resourceType,
		// Parent Scope ID will be filled in via performAuthCheck
	}
	// Global scope has no parent ID; account for this
	if opts.withId == scope.Global.String() && resourceType == resource.Scope {
		v.res.ScopeId = scope.Global.String()
	}

	if v.requestInfo.EncryptedToken != "" {
		v.decryptToken(ctx)
	}

	resourcesToFetchGrants := append([]resource.Type{resourceType}, opts.withFetchAdditionalResourceGrants...)

	var authResults perms.ACLResults
	var userData template.Data
	var err error
	authResults, ret.UserData, ret.Scope, v.acl, ret.grants, err = v.performAuthCheck(ctx, resourcesToFetchGrants, opts.withRecursive)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error performing authn/authz check"))
		return ret
	}

	if ret.UserData.User.Id != nil {
		ret.UserId = *ret.UserData.User.Id
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
			if ret.UserId == globals.AnonymousUserId {
				ret.Error = handlers.UnauthenticatedError()
			}
			ea.UserInfo = &event.UserInfo{
				UserId: ret.UserId,
			}
			return ret
		}
	}

	grants := make([]event.Grant, 0, len(ret.grants))
	for _, g := range ret.grants {
		grants = append(grants, event.Grant{
			Grant:   g.Grant,
			RoleId:  g.RoleId,
			ScopeId: g.GrantScopeId,
		})
	}
	ea.UserInfo = &event.UserInfo{
		UserId: ret.UserId,
	}
	if userData.Account.Id != nil {
		ea.UserInfo.AuthAccountId = *userData.Account.Id
	}
	ea.GrantsInfo = &event.GrantsInfo{
		Grants: grants,
	}
	if userData.User.FullName != nil {
		ea.UserName = *userData.User.FullName
	}
	if userData.User.Email != nil {
		ea.UserEmail = *userData.User.Email
	}

	if reqInfo != nil {
		reqInfo.UserId = ret.UserId
		reqInfo.OutputFields = authResults.OutputFields
	}

	ret.Error = nil
	return ret
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
		wrapper := v.kms.GetExternalWrappers(ctx).Recovery()
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
			event.WriteError(ctx, op, err, event.WithInfoMsg("decrypt recovery token: error fetching server repo"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}
		if err := repo.AddNonce(v.ctx, info.Nonce, server.NoncePurposeRecovery); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("decrypt recovery token: error adding nonce to database (possible replay attack)"))
			v.requestInfo.TokenFormat = uint32(AuthTokenTypeUnknown)
			return
		}
		event.WriteError(ctx, op, stderrors.New("recovery KMS was used to authorize a call"), event.WithInfo("url", v.requestInfo.Path, "method", v.requestInfo.Method))
	}
}

func (v verifier) performAuthCheck(ctx context.Context, resourceType []resource.Type, isRecursiveRequest bool) (
	aclResults perms.ACLResults,
	userData template.Data,
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

	// This will always be set, so further down below we can switch on whether
	// it's empty
	userData.User.Id = util.Pointer(globals.AnonymousUserId)

	// Validate the token and fetch the corresponding user ID
	switch v.requestInfo.TokenFormat {
	case uint32(AuthTokenTypeUnknown):
		// Nothing; remain as the anonymous user

	case uint32(AuthTokenTypeRecoveryKms):
		// We validated the encrypted token in decryptToken and handled the
		// nonces there, so just set the user
		userData.User.Id = util.Pointer(globals.RecoveryUserId)

	case uint32(AuthTokenTypeBearer), uint32(AuthTokenTypeSplitCookie):
		if v.requestInfo.Token == "" {
			// This will end up staying as the anonymous user
			break
		}
		tokenRepo, err := v.authTokenRepoFn()
		if err != nil {
			retErr = errors.Wrap(ctx, err, op)
			return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
		}
		at, err := tokenRepo.ValidateToken(v.ctx, v.requestInfo.PublicId, v.requestInfo.Token)
		if err != nil {
			// Continue as the anonymous user as maybe this token is expired but
			// we can still perform the action
			event.WriteError(ctx, op, err, event.WithInfoMsg("error validating token; continuing as anonymous user"))
			break
		}
		if at != nil {
			userData.Account.Id = util.Pointer(at.GetAuthAccountId())
			userData.User.Id = util.Pointer(at.GetIamUserId())
			if *userData.User.Id == "" {
				event.WriteError(ctx, op, stderrors.New("perform auth check: valid token did not map to a user, likely because no account is associated with the user any longer; continuing as u_anon"), event.WithInfo("token_id", at.GetPublicId()))
				userData.User.Id = util.Pointer(globals.AnonymousUserId)
				userData.Account.Id = nil
			}
		}
	}

	iamRepo, err := v.iamRepoFn()
	if err != nil {
		retErr = errors.Wrap(ctx, err, op, errors.WithMsg("failed to get iam repo"))
		return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
	}

	u, _, err := iamRepo.LookupUser(ctx, *userData.User.Id)
	if err != nil {
		retErr = errors.Wrap(ctx, err, op, errors.WithMsg("failed to lookup user"))
		return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
	}
	userData.User.Name = util.Pointer(u.Name)
	userData.User.Email = util.Pointer(u.Email)
	userData.User.FullName = util.Pointer(u.FullName)

	if userData.Account.Id != nil && *userData.Account.Id != "" && v.passwordAuthRepoFn != nil && v.oidcAuthRepoFn != nil && v.ldapAuthRepoFn != nil {
		const domain = "auth"
		var acct auth.Account
		var err error
		switch globals.ResourceInfoFromPrefix(*userData.Account.Id).Subtype {
		case password.Subtype:
			repo, repoErr := v.passwordAuthRepoFn()
			if repoErr != nil {
				retErr = errors.Wrap(ctx, repoErr, op, errors.WithMsg("failed to get password auth repo"))
				return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
			}
			acct, err = repo.LookupAccount(ctx, *userData.Account.Id)
		case oidc.Subtype:
			repo, repoErr := v.oidcAuthRepoFn()
			if repoErr != nil {
				retErr = errors.Wrap(ctx, repoErr, op, errors.WithMsg("failed to get oidc auth repo"))
				return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
			}
			acct, err = repo.LookupAccount(ctx, *userData.Account.Id)
		case ldap.Subtype:
			repo, repoErr := v.ldapAuthRepoFn()
			if repoErr != nil {
				retErr = errors.Wrap(ctx, repoErr, op, errors.WithMsg("failed to get ldap auth repo"))
				return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
			}
			acct, err = repo.LookupAccount(ctx, *userData.Account.Id)
		default:
			retErr = errors.Wrap(ctx, err, op, errors.WithMsg("unrecognized account id type"))
			return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
		}
		if err != nil {
			if errors.IsNotFoundError(err) {
				retErr = errors.Wrap(ctx, err, op, errors.WithMsg("account doesn't exist"))
				return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
			}
			retErr = errors.Wrap(ctx, err, op, errors.WithMsg("error looking up account"))
			return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
		}
		userData.Account.Name = util.Pointer(acct.GetName())
		userData.Account.Email = util.Pointer(acct.GetEmail())
		userData.Account.LoginName = util.Pointer(acct.GetLoginName())
		userData.Account.Subject = util.Pointer(acct.GetSubject())
	}

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
			return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
		}
		if scp == nil {
			retErr = errors.New(ctx, errors.InvalidParameter, op, fmt.Sprint("non-existent scope $q", v.res.ScopeId))
			return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
		}
		scopeInfo = &scopes.ScopeInfo{
			Id:            scp.GetPublicId(),
			Type:          scp.GetType(),
			Name:          scp.GetName(),
			Description:   scp.GetDescription(),
			ParentScopeId: scp.GetParentId(),
		}
	}
	v.res.ParentScopeId = scopeInfo.ParentScopeId

	// At this point we don't need to look up grants since it's automatically allowed
	if v.requestInfo.TokenFormat == uint32(AuthTokenTypeRecoveryKms) {
		aclResults.AuthenticationFinished = true
		aclResults.Authorized = true
		retErr = nil
		return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
	}

	var parsedGrants []perms.Grant

	// Fetch and parse grants for this user ID (which may include grants for
	// u_anon and u_auth)
	iamOpt := []iam.Option{iam.WithRecursive(isRecursiveRequest)}
	grantTuples, err = iamRepo.GrantsForUser(v.ctx, *userData.User.Id, resourceType, scopeInfo.Id, iamOpt...)
	if err != nil {
		retErr = errors.Wrap(ctx, err, op)
		return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
	}
	parsedGrants = make([]perms.Grant, 0, len(grantTuples))
	// Note: Below, we always skip validation so that we don't error on formats
	// that we've since restricted, e.g. "ids=foo;actions=create,read". These
	// will simply not have an effect.
	for _, tuple := range grantTuples {
		permsOpts := []perms.Option{
			perms.WithUserId(*userData.User.Id),
			perms.WithSkipFinalValidation(true),
		}
		if userData.Account.Id != nil {
			permsOpts = append(permsOpts, perms.WithAccountId(*userData.Account.Id))
		}
		parsed, err := perms.Parse(
			ctx,
			tuple,
			permsOpts...)
		if err != nil {
			retErr = errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed to parse grant %#v", tuple.Grant)))
			return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
		}
		parsedGrants = append(parsedGrants, parsed)
	}

	retAcl = perms.NewACL(parsedGrants...)
	aclResults = retAcl.Allowed(*v.res, v.act, *userData.User.Id)
	// We don't set authenticated above because setting this but not authorized
	// is used for further permissions checks, such as during recursive listing.
	// So we want to make sure any code relying on that has the full set of
	// grants successfully loaded.
	aclResults.AuthenticationFinished = true
	retErr = nil
	return aclResults, userData, scopeInfo, retAcl, grantTuples, retErr
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

	// If there is no user ID set by definition there are no actions to fetch.
	// This shouldn't happen because we should always fall back to at least the
	// anonymous user so it's defense in depth.
	if r.UserData.User.Id == nil {
		return nil
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

	ret := make(action.ActionSet, len(availableActions))
	for act := range availableActions {
		if r.v.acl.Allowed(*res, act, *r.UserData.User.Id).Authorized {
			ret.Add(act)
		}
	}
	if len(ret) == 0 {
		return nil
	}
	return ret
}

func (r *VerifyResults) FetchOutputFields(res perms.Resource, act action.Type) *perms.OutputFields {
	var ret *perms.OutputFields
	switch {
	case r.v.requestInfo.TokenFormat == uint32(AuthTokenTypeRecoveryKms):
		return ret.AddFields([]string{"*"})
	case r.v.requestInfo.DisableAuthEntirely:
		return ret
	case r.UserData.User.Id == nil:
		// If there is no user ID set by definition there are no actions to fetch.
		// This shouldn't happen because we should always fall back to at least the
		// anonymous user so it's defense in depth.
		return ret
	}

	return r.v.acl.Allowed(res, act, *r.UserData.User.Id).OutputFields
}

// ACL returns the perms.ACL of the verifier.
func (r *VerifyResults) ACL() perms.ACL {
	if r.v == nil {
		return perms.ACL{}
	}

	return r.v.acl
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
		// the anonymous user
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

// ScopesAuthorizedForList retrieves and returns all scopes where a user is authorized
// to perform a *list* action on. It looks recursively from `rootScopeId`.
func (r *VerifyResults) ScopesAuthorizedForList(ctx context.Context, rootScopeId string, resourceType resource.Type) (map[string]*scopes.ScopeInfo, error) {
	const op = "auth.(VerifyResults).ScopesAuthorizedForList"

	// Validation
	switch {
	case resourceType == resource.Unknown:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unknown resource")
	case r.v.iamRepoFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil iam repo")
	case rootScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root scope id")
	case r.Scope == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil scope in auth results")
	}

	repo, err := r.v.iamRepoFn()
	if err != nil {
		return nil, err
	}

	// Get all scopes recursively. Start at global because we need to take into
	// account permissions in parent scopes even if they want to scale back the
	// returned information to a child scope and its children.
	scps, err := repo.ListScopesRecursively(ctx, scope.Global.String())
	if err != nil {
		return nil, err
	}

	var deferredScopes []*iam.Scope
	var globalHasList bool                                 // Store whether global has list permission
	scopeResourceMap := make(map[string]*scopes.ScopeInfo) // Scope data per scope id

	// For each scope, see if we have permission to list that resource in that scope
	for _, scp := range scps {
		scpId := scp.GetPublicId()
		aSet := r.FetchActionSetForType(ctx,
			resource.Unknown, // This is overridden by `WithResource` option.
			action.NewActionSet(action.List),
			WithResource(&perms.Resource{Type: resourceType, ScopeId: scpId, ParentScopeId: scp.GetParentId()}),
		)

		// We only expect the action set to be nothing, or list. In case
		// this is not the case, we bail out.
		switch {
		case len(aSet) == 0:
			// Defer until we've read all scopes. We do this because if the
			// ordering coming back isn't in parent-first ordering our map
			// lookup might fail.
			deferredScopes = append(deferredScopes, scp)
		case len(aSet) == 1 || r.UserId == globals.RecoveryUserId:
			if !aSet.HasAction(action.List) {
				return nil, errors.New(ctx, errors.Internal, op, "unexpected action in set")
			}
			if scopeResourceMap[scpId] == nil {
				scopeResourceMap[scpId] = &scopes.ScopeInfo{
					Id:            scp.GetPublicId(),
					Type:          scp.GetType(),
					Name:          scp.GetName(),
					Description:   scp.GetDescription(),
					ParentScopeId: scp.GetParentId(),
				}
			}
			if scpId == scope.Global.String() {
				globalHasList = true
			}
		default:
			return nil, errors.New(ctx, errors.Internal, op, "unexpected number of actions back in set")
		}
	}

	// Now go through the deferred scopes and see if a parent matches
	for _, scp := range deferredScopes {
		// If they had list on global scope anything else is automatically
		// included; otherwise if they had list on the parent scope, this
		// scope is included in the map and is sufficient here.
		if globalHasList || scopeResourceMap[scp.GetParentId()] != nil {
			scpId := scp.GetPublicId()
			if scopeResourceMap[scpId] == nil {
				scopeResourceMap[scpId] = &scopes.ScopeInfo{
					Id:            scp.GetPublicId(),
					Type:          scp.GetType(),
					Name:          scp.GetName(),
					Description:   scp.GetDescription(),
					ParentScopeId: scp.GetParentId(),
				}
			}
		}
	}

	// Elide out any that aren't under the root scope id
	elideScopes := make([]string, 0, len(scopeResourceMap))
	for scpId, scp := range scopeResourceMap {
		switch rootScopeId {
		// If the root is global, it matches
		case scope.Global.String():
		// If the current scope matches the root, it matches
		case scpId:
			// Or if the parent of this scope is the root (for orgs that would mean
			// a root scope ID which is covered in the case above, so this is really
			// projects matching an org used as the root)
		case scp.ParentScopeId:
		default:
			elideScopes = append(elideScopes, scpId)
		}
	}
	for _, scpId := range elideScopes {
		delete(scopeResourceMap, scpId)
	}

	// If we have nothing in scopeInfoMap at this point, we aren't authorized
	// anywhere so return 403.
	if len(scopeResourceMap) == 0 {
		return nil, handlers.ForbiddenError()
	}

	return scopeResourceMap, nil
}

// GrantsHash returns a stable hash of all the grants in the verify results.
func (r *VerifyResults) GrantsHash(ctx context.Context) ([]byte, error) {
	return r.grants.GrantHash(ctx)
}

// GetRequestInfo extracts the request info stored in the context, if it exists.
// This returns nil, false if the request info could not be found.
func GetRequestInfo(ctx context.Context) (*authpb.RequestInfo, bool) {
	v, ok := ctx.Value(verifierKey).(*verifier)
	if !ok {
		return nil, false
	}
	return v.requestInfo, true
}
