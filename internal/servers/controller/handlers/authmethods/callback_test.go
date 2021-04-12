package authmethods

import (
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestErrorResponseBuilder(t *testing.T) {
	cases := []struct{
		name string
		apiUrl string
		err error
		wantRedirectUrl string
	} {
		{
			name: "domain error",
			apiUrl: "http://example.com",
			err: errors.New(errors.InvalidParameter, "op", "example error"),
			wantRedirectUrl: "http://example.com/authentication-error?error=" + url.QueryEscape(errors.New(errors.InvalidParameter, "op", "example error").Error()),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := errorResponseBuilder(tc.apiUrl)(tc.err)
			want := &pbs.AuthenticateResponse{
				Command: callbackCommand,
			}
			attrs := &pb.OidcAuthMethodAuthenticateCallbackResponse{FinalRedirectUrl: tc.wantRedirectUrl}
			var err error
			want.Attributes, err = handlers.ProtoToStruct(attrs)
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(got, want, protocmp.Transform()))
		})
	}
}