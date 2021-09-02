package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authtokenpb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"

	"google.golang.org/protobuf/proto"
)

const (
	HttpOnlyCookieName    = "wt-http-token-cookie"
	JsVisibleCookieName   = "wt-js-token-cookie"
	tokenTypeField        = "token_type"
	finalRedirectUrlField = "final_redirect_url"
	statusField           = "status"
)

func OutgoingInterceptor(ctx context.Context, w http.ResponseWriter, m proto.Message) error {
	m = m.ProtoReflect().Interface()
	if !m.ProtoReflect().IsValid() {
		// This would be the case if it's a nil pointer
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	switch m := m.(type) {
	case *pbs.AuthenticateResponse:
		if m.GetAttributes() == nil || m.GetAttributes().GetFields() == nil {
			// We may not have a token depending on the subcommand; nothing to
			// do if there are no attributes
			return nil
		}
		fields := m.GetAttributes().GetFields()
		if m.GetCommand() == "token" {
			if _, ok := fields[statusField]; ok {
				// For now at least status will never be anything useful so
				// don't need to check on it; the mere presence is enough to
				// know what to do
				w.WriteHeader(http.StatusAccepted)
				return nil
			}
		}
		// It's a redirect
		if urlField, ok := fields[finalRedirectUrlField]; ok {
			u := urlField.GetStringValue()
			if u == "" {
				return fmt.Errorf("unable to convert final request url to string")
			}
			delete(fields, finalRedirectUrlField)
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
			return nil
		}
		// It's a token response
		if _, ok := fields[tokenTypeField]; ok {
			aToken := &authtokenpb.AuthToken{}
			// We may have "token_type" if it's a token, or it may not be a token at
			// all, so ignore unknown fields
			if err := StructToProto(m.GetAttributes(), aToken, WithDiscardUnknownFields(true)); err != nil {
				return err
			}
			tokenType := m.GetAttributes().GetFields()[tokenTypeField].GetStringValue()
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
