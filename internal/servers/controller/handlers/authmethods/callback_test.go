package authmethods

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestErrorResponseBuilder(t *testing.T) {
	apiUrl := "http://example.com"
	inErr := fmt.Errorf("example error")

	got := errorResponseBuilder(apiUrl)(inErr)

	want := &pbs.AuthenticateResponse{
		Command: callbackCommand,
	}
	attrs := &pb.OidcAuthMethodAuthenticateCallbackResponse{
		FinalRedirectUrl: "http://example.com/authentication-error?error=example+error",
	}
	var err error
	want.Attributes, err = handlers.ProtoToStruct(attrs)
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(got, want, protocmp.Transform()))
}
