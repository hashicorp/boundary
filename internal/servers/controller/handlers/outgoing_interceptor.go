package handlers

import (
	"context"
	"net/http"
	"strings"

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
