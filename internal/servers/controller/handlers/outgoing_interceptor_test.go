package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/stretchr/testify/assert"
)

func TestOutgoingSplitCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	OutgoingIntercepter(context.Background(), rec, &pbs.AuthenticateResponse{
		TokenType: "cookie",
		Item:      &pb.AuthToken{Token: "t_abc_1234567890"},
	})
	assert.ElementsMatch(t, rec.Result().Cookies(), []*http.Cookie{
		{Name: HttpOnlyCookieName, Value: "34567890", HttpOnly: true, Raw: "wt-http-token-cookie=34567890; HttpOnly"},
		{Name: JsVisibleCookieName, Value: "t_abc_12", Raw: "wt-js-token-cookie=t_abc_12"},
	})
}
