package handlers

import (
	"context"
	"net/http"
	"strings"

	authtokenpb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"

	"google.golang.org/protobuf/proto"
)

const (
	HttpOnlyCookieName  = "wt-http-token-cookie"
	JsVisibleCookieName = "wt-js-token-cookie"
)

func OutgoingInterceptor(ctx context.Context, w http.ResponseWriter, m proto.Message) error {
	m = m.ProtoReflect().Interface()
	switch m := m.(type) {
	case *pbs.AuthenticateResponse:
		if m.GetAttributes() == nil || m.GetAttributes().GetFields() == nil {
			// We may not have a token depending on the subcommand; nothing to
			// do if there are no attributes
			return nil
		}
		aToken := &authtokenpb.AuthToken{}
		// We may have "token_type" if it's a token, or it may not be a token at
		// all, so ignore unknown fields
		if err := StructToProto(m.GetAttributes(), aToken, WithDiscardUnknownFields(true)); err != nil {
			return err
		}
		tokenType := m.GetAttributes().GetFields()["token_type"].GetStringValue()
		if strings.EqualFold(tokenType, "cookie") {
			tok := aToken.GetToken()
			if tok == "" {
				// Response did not include a token, continue
				return nil
			}
			delete(m.GetAttributes().GetFields(), "token")
			half := len(tok) / 2
			jsTok := http.Cookie{
				Name:  JsVisibleCookieName,
				Value: tok[:half],
			}
			httpTok := http.Cookie{
				Name:     HttpOnlyCookieName,
				Value:    tok[half:],
				HttpOnly: true,
			}
			http.SetCookie(w, &jsTok)
			http.SetCookie(w, &httpTok)
		}
	case *pbs.AuthenticateLoginResponse:
		if strings.EqualFold(m.GetTokenType(), "cookie") {
			tok := m.GetItem().GetToken()
			m.GetItem().Token = ""
			half := len(tok) / 2
			jsTok := http.Cookie{
				Name:  JsVisibleCookieName,
				Value: tok[:half],
			}
			httpTok := http.Cookie{
				Name:     HttpOnlyCookieName,
				Value:    tok[half:],
				HttpOnly: true,
			}
			http.SetCookie(w, &jsTok)
			http.SetCookie(w, &httpTok)
		}
	}

	return nil
}
