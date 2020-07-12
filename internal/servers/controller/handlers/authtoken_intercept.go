package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/watchtower/globals"
	"github.com/hashicorp/watchtower/internal/perms"
	"github.com/hashicorp/watchtower/internal/servers/controller/common"
	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/kr/pretty"
	"google.golang.org/grpc/metadata"
)

const (
	headerAuthMethod    = "Authorization"
	httpOnlyCookieName  = "wt-http-token-cookie"
	jsVisibleCookieName = "wt-js-token-cookie"
)

// TokenAuthenticator returns a function that can be used in grpc-gateway's runtime.WithMetadata ServerOption.
// It looks at the cookies and headers of the incoming request and returns metadata that can later be
// used by handlers to build a TokenMetadata using the ToTokenMetadata function.
func TokenAuthenticator(l hclog.Logger, tokenRepo common.AuthTokenRepoFactory, iamRepo common.IamRepoFactory) func(context.Context, *http.Request) metadata.MD {
	return func(ctx context.Context, req *http.Request) metadata.MD {
		tMD := TokenMetadata{}
		if authHeader := req.Header.Get(headerAuthMethod); authHeader != "" {
			headerSplit := strings.SplitN(strings.TrimSpace(authHeader), " ", 2)
			if len(headerSplit) == 2 && strings.EqualFold(strings.TrimSpace(headerSplit[0]), "bearer") {
				tMD.receivedTokenType = authTokenTypeBearer
				tMD.bearerPayload = strings.TrimSpace(headerSplit[1])
			}
		}
		if tMD.receivedTokenType != authTokenTypeBearer {
			if hc, err := req.Cookie(httpOnlyCookieName); err == nil {
				tMD.httpCookiePayload = hc.Value
			}
			if jc, err := req.Cookie(jsVisibleCookieName); err == nil {
				tMD.jsCookiePayload = jc.Value
			}
			if tMD.httpCookiePayload != "" && tMD.jsCookiePayload != "" {
				tMD.receivedTokenType = authTokenTypeSplitCookie
			}
		}

		if tMD.receivedTokenType == authTokenTypeUnknown || tMD.token() == "" || tMD.publicId() == "" {
			return tMD.toMetadata()
		}

		tokenRepo, err := tokenRepo()
		if err != nil {
			l.Error("failed to get authtoken repo", "error", err)
			return tMD.toMetadata()
		}

		at, err := tokenRepo.ValidateToken(ctx, tMD.publicId(), tMD.token())
		if err != nil {
			l.Error("failed to validate token", "error", err)
		}
		if at != nil {
			tMD.UserId = at.GetIamUserId()
		} else {
			tMD.UserId = "u_anon"
		}

		iamRepo, err := iamRepo()
		if err != nil {
			l.Error("failed to get iam repo", "error", err)
			return tMD.toMetadata()
		}
		grantPairs, err := iamRepo.GrantsForUser(ctx, tMD.UserId)
		if err != nil {
			l.Error("failed to query for user grants", "error", err)
			return tMD.toMetadata()
		}
		parsedGrants := make([]perms.Grant, 0, len(grantPairs))
		for _, pair := range grantPairs {
			parsed, err := perms.Parse(pair.ScopeId, tMD.UserId, pair.Grant)
			if err != nil {
				l.Error("failed to parse grant", "grant", pair.Grant, "error", err)
				return tMD.toMetadata()
			}
			parsedGrants = append(parsedGrants, parsed)
		}

		var scopeId, id, pin string
		var typ resource.Type
		var act action.Type
		typRaw := ctx.Value(globals.ContextTypeValue)
		if typRaw != nil {
			typ = typRaw.(resource.Type)
		}
		scopeIdRaw := ctx.Value(globals.ContextScopeValue)
		if scopeIdRaw != nil {
			scopeId = scopeIdRaw.(string)
		}
		actRaw := ctx.Value(globals.ContextActionValue)
		if actRaw != nil {
			act = actRaw.(action.Type)
		}
		idRaw := ctx.Value(globals.ContextResourceValue)
		if idRaw != nil {
			id = idRaw.(string)
		}
		pinRaw := ctx.Value(globals.ContextPinValue)
		if pinRaw != nil {
			pin = pinRaw.(string)
		}

		acl := perms.NewACL(parsedGrants...)
		res := perms.Resource{
			// These values were parsed from the request information
			ScopeId: scopeId,
			Type:    typ,
			Id:      id,
			Pin:     pin,
		}
		allowed := acl.Allowed(res, act)
		if allowed.Allowed {
			tMD.authorized = true
		}
		l.Info("grant checking", "user_id", tMD.UserId, "grants", pretty.Sprint(grantPairs), "resource", res, "authorized", allowed)

		return tMD.toMetadata()
	}
}

type tokenFormat int

const (
	authTokenTypeUnknown tokenFormat = iota
	authTokenTypeBearer
	authTokenTypeSplitCookie
)

// TokenMetadata allows easy writing/reading of tokens to clients and authenticating the provided token.
// Expected usage for authorization is
// func (s *Service) GetResource(ctx context.Context, req GetResourceRequest) (GetResourceResponse, error) {
//		amd := handlers.ToTokenMetadata(ctx)
//      if !authorizer.isAuthorized(amd.UserId, "ReadResource", req.GetId()) { return nil, UnauthorizedError }
//      ...
//
// A new token will be created by the Authenticate method on an Org.  The token value will be returned
// through json and not be intercepted by these tools.
// TODO: Intercept the outgoing Authenticate/Deauthenticate response and manipulate
//  the response if the token type was cookie.
type TokenMetadata struct {
	// Only set the UserId if the token was found and was not expired.
	UserId string

	authorized bool

	receivedTokenType tokenFormat
	bearerPayload     string

	jsCookiePayload   string
	httpCookiePayload string
}

const (
	mdAuthTokenUserKey        = "wt-authtoken-user-key"
	mdAuthAuthorizedKey       = "wt-authtoken-authorized"
	mdAuthTokenBearerTokenKey = "wt-authtoken-bearer-token-key"
	mdAuthTokenHttpTokenKey   = "wt-authtoken-http-token-key"
	mdAuthTokenJsTokenKey     = "wt-authtoken-js-token-key"
	mdAuthTokenTypeKey        = "wt-authtoken-type-key"
)

// ToTokenMetadata takes an incoming context and builds a TokenMetadata based on the metadata attached to it.
// If the context has no TokenMetadata attached to it an empty TokenMetadata is returned.
func ToTokenMetadata(ctx context.Context) TokenMetadata {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return TokenMetadata{}
	}
	tMD := TokenMetadata{}
	if uid := md.Get(mdAuthTokenUserKey); len(uid) > 0 {
		tMD.UserId = uid[0]
	}
	if authzd := md.Get(mdAuthAuthorizedKey); len(authzd) > 0 {
		tMD.authorized = authzd[0] == "true"
	}
	if token := md.Get(mdAuthTokenBearerTokenKey); len(token) > 0 {
		tMD.bearerPayload = token[0]
	}
	if token := md.Get(mdAuthTokenHttpTokenKey); len(token) > 0 {
		tMD.httpCookiePayload = token[0]
	}
	if token := md.Get(mdAuthTokenJsTokenKey); len(token) > 0 {
		tMD.jsCookiePayload = token[0]
	}
	if sType := md.Get(mdAuthTokenTypeKey); len(sType) > 0 {
		if st, err := strconv.Atoi(sType[0]); err == nil {
			tMD.receivedTokenType = tokenFormat(st)
		}
	}

	return tMD
}

func (s TokenMetadata) toMetadata() metadata.MD {
	md := metadata.MD{}
	if s.UserId != "" {
		md.Set(mdAuthTokenUserKey, s.UserId)
	}
	if s.authorized {
		md.Set(mdAuthAuthorizedKey, "true")
	} else {
		md.Set(mdAuthAuthorizedKey, "false")
	}
	if s.bearerPayload != "" {
		md.Set(mdAuthTokenBearerTokenKey, s.bearerPayload)
	}
	if s.httpCookiePayload != "" {
		md.Set(mdAuthTokenHttpTokenKey, s.httpCookiePayload)
	}
	if s.jsCookiePayload != "" {
		md.Set(mdAuthTokenJsTokenKey, s.jsCookiePayload)
	}
	if s.receivedTokenType != authTokenTypeUnknown {
		md.Set(mdAuthTokenTypeKey, fmt.Sprint(s.receivedTokenType))
	}

	return md
}

// publicId returns the public id parsed out of the provided auth token.  If the provided auth token
// is malformed then this returns an empty string.
func (s TokenMetadata) publicId() string {
	tok := ""
	switch s.receivedTokenType {
	case authTokenTypeBearer:
		tok = s.bearerPayload
	case authTokenTypeSplitCookie:
		tok = s.jsCookiePayload + s.httpCookiePayload
	}
	l := strings.Split(tok, "_")[:strings.Count(tok, "_")]
	if len(l) != 2 {
		return ""
	}
	return strings.Join(l, "_")
}

// token returns the token value parsed out of the provided auth token.  If the provided auth token
// is malformed then this returns an empty string.
func (s TokenMetadata) token() string {
	var tok string
	switch s.receivedTokenType {
	case authTokenTypeBearer:
		tok = s.bearerPayload
	case authTokenTypeSplitCookie:
		tok = s.jsCookiePayload + s.httpCookiePayload
	}
	l := strings.Split(tok, "_")
	if len(l) != 3 {
		return ""
	}
	return l[2]
}
