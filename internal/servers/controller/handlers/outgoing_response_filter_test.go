package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestOutgoingSplitCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	attrs, err := ProtoToStruct(&pb.AuthToken{Token: "t_abc_1234567890"})
	require.NoError(t, err)
	attrs.GetFields()["token_type"] = structpb.NewStringValue("cookie")
	require.NoError(t, OutgoingResponseFilter(context.Background(), rec, &pbs.AuthenticateResponse{Attributes: attrs}))
	assert.ElementsMatch(t, rec.Result().Cookies(), []*http.Cookie{
		{Name: HttpOnlyCookieName, Value: "34567890", HttpOnly: true, Raw: "wt-http-token-cookie=34567890; HttpOnly"},
		{Name: JsVisibleCookieName, Value: "t_abc_12", Raw: "wt-js-token-cookie=t_abc_12"},
	})
}
