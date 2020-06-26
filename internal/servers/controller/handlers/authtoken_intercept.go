package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc/metadata"
)

const (
	headerAuthMethod    = "Authorization"
	httpOnlyCookieName  = "wt-http-token-cookie"
	jsVisibleCookieName = "wt-js-token-cookie"
)

const (
	defaultAuthTokenDuration = time.Hour * 24
)

// TokenAuthenticator returns a function that can be used in grpc-gateway's runtime.WithMetadata ServerOption.
// It looks at the cookies and headers of the incoming request and returns metadata that can later be
// used by handlers to build a TokenMetadata using the ToTokenMetadata function.
func TokenAuthenticator(l hclog.Logger) func(context.Context, *http.Request) metadata.MD {
	return func(ctx context.Context, req *http.Request) metadata.MD {
		tMD := TokenMetadata{}
		if hc, err := req.Cookie(httpOnlyCookieName); err == nil {
			tMD.httpCookiePayload = hc.Value
		}
		if jc, err := req.Cookie(jsVisibleCookieName); err == nil {
			tMD.jsCookiePayload = jc.Value
		}
		if tMD.httpCookiePayload != "" && tMD.jsCookiePayload != "" {
			tMD.recievedTokenType = authTokenTypeSplitCookie
		}

		if authHeader := req.Header.Get(headerAuthMethod); authHeader != "" {
			headerSplit := strings.SplitN(strings.TrimSpace(authHeader), " ", 2)
			if len(headerSplit) == 2 && strings.EqualFold(strings.TrimSpace(headerSplit[0]), "bearer") {
				tMD.recievedTokenType = authTokenTypeBearer
				tMD.bearerPayload = strings.TrimSpace(headerSplit[1])
			}
		}

		// TODO: - Lookup/maybe update the last used time of this token,
		//       - Validate the returned token's expiration time after now()
		//       - Validate now().Sub(last used time) < defaultAuthTokenDuration
		//       - If all those are correct, set the tMD.UserId to the returned token's userid.

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
// A new token will be created by the Authenticate method on an Organization.  The token value will be returned
// through json and not be intercepted by these tools.
// TODO: Intercept the outgoing Authenticate/Deauthenticate response and manipulate
//  the response if the token type was cookie.
type TokenMetadata struct {
	// Only set the UserId if the token was found and was not expired.
	UserId string

	recievedTokenType tokenFormat
	bearerPayload     string

	jsCookiePayload   string
	httpCookiePayload string
}

const (
	mdAuthTokenUserKey        = "wt-authtoken-user-key"
	mdAuthTokenBearerTokenKey = "wt-authtoken-bearer-token-key"
	mdAuthTokenHttpTokenKey   = "wt-authtoken-http-token-key"
	mdAuthTokenJsTokenKey     = "wt-authtoken-js-token-key"
	mdAuthTokenTypeKey        = "wt-authtoken-type-key"
)

// ToTokenMetadata takes an incoming context and builds a TokenMetadata based on the metadata attached to it.
// If the context has no incoming metadata attached to it an error is returned.  If no TokenMetadata related
// // metadata is attached to it an empty TokenMetadata is returned.
func ToTokenMetadata(ctx context.Context) (TokenMetadata, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return TokenMetadata{}, fmt.Errorf("Provided context was not an incoming grpc metadta")
	}
	s := TokenMetadata{}
	if uid := md.Get(mdAuthTokenUserKey); len(uid) > 0 {
		s.UserId = uid[0]
	}
	if token := md.Get(mdAuthTokenBearerTokenKey); len(token) > 0 {
		s.bearerPayload = token[0]
	}
	if token := md.Get(mdAuthTokenHttpTokenKey); len(token) > 0 {
		s.httpCookiePayload = token[0]
	}
	if token := md.Get(mdAuthTokenJsTokenKey); len(token) > 0 {
		s.jsCookiePayload = token[0]
	}
	if sType := md.Get(mdAuthTokenTypeKey); len(sType) > 0 {
		if st, err := strconv.Atoi(sType[0]); err == nil {
			s.recievedTokenType = tokenFormat(st)
		}
	}

	return s, nil
}

func (s TokenMetadata) toMetadata() metadata.MD {
	md := metadata.MD{}
	if s.UserId != "" {
		md.Set(mdAuthTokenUserKey, s.UserId)
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
	if s.recievedTokenType != authTokenTypeUnknown {
		md.Set(mdAuthTokenTypeKey, fmt.Sprint(s.recievedTokenType))
	}
	return md
}

func (s TokenMetadata) publicId() string {
	switch s.recievedTokenType {
	case authTokenTypeBearer:
		return strings.Split(s.bearerPayload, ".")[0]
	case authTokenTypeSplitCookie:
		return strings.Split(s.jsCookiePayload, ".")[0]
	}
	return ""
}

func (s TokenMetadata) token() string {
	switch s.recievedTokenType {
	case authTokenTypeBearer:
		return strings.Split(s.bearerPayload, ".")[strings.Count(s.bearerPayload, ".")]
	case authTokenTypeSplitCookie:
		tok := s.jsCookiePayload + s.httpCookiePayload
		return strings.Split(tok, ".")[strings.Count(tok, ".")]
	}
	return ""
}
