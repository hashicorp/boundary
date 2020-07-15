package authtokens_test

import (
	"context"
	"net/http"
	"sort"
	"testing"

	"github.com/hashicorp/watchtower/api/authtokens"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/authtoken"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthTokens_List(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}
	ctx := context.Background()

	atl, apiErr, err := org.ListAuthTokens(ctx)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(atl)

	var expected []*authtokens.AuthToken

	at, apiErr, err := org.Authenticate(ctx, "am_1234567890", "name", "pw")
	assert.NoError(err)
	assert.Nil(apiErr)
	expected = append(expected, at)

	atl, apiErr, err = org.ListAuthTokens(ctx)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(atl))

	for i := 1; i < 10; i++ {
		at, apiErr, err = org.Authenticate(ctx, "am_1234567890", "name", "pw")
		assert.NoError(err)
		assert.Nil(apiErr)
		expected = append(expected, at)
	}
	atl, apiErr, err = org.ListAuthTokens(ctx)
	require.NoError(t, err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(atl))
}

func comparableResource(i *authtokens.AuthToken) authtokens.AuthToken {
	return authtokens.AuthToken{
		Id:                      i.Id,
		UserId:                  i.UserId,
		AuthMethodId:            i.AuthMethodId,
		CreatedTime:             i.CreatedTime,
		UpdatedTime:             i.UpdatedTime,
		ApproximateLastUsedTime: i.ApproximateLastUsedTime,
		ExpirationTime:          i.ExpirationTime,
	}
}

func comparableSlice(in []*authtokens.AuthToken) []authtokens.AuthToken {
	var filtered []authtokens.AuthToken
	for _, i := range in {
		filtered = append(filtered, comparableResource(i))
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Id < filtered[j].Id
	})
	return filtered
}

func TestAuthToken_Crud(t *testing.T) {
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}

	want, apiErr, err := org.Authenticate(tc.Context(), "am_1234567890", "name", "pw")

	at, apiErr, err := org.ReadAuthToken(tc.Context(), &authtokens.AuthToken{Id: want.Id})
	require.NoError(t, err)
	assert.Nil(t, apiErr)
	at.Token = ""
	assert.EqualValues(t, comparableResource(want), comparableResource(at))

	existed, _, err := org.DeleteAuthToken(tc.Context(), at)
	require.NoError(t, err)
	assert.Nil(t, apiErr)
	assert.True(t, existed, "Expected existing user when deleted, but it wasn't.")

	existed, apiErr, err = org.DeleteAuthToken(tc.Context(), at)
	require.NoError(t, err)
	assert.Nil(t, apiErr)
	assert.False(t, existed, "Expected user to not exist when deleted, but it did.")
}

func TestAuthToken_Errors(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()
	ctx := tc.Context()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}

	_, apiErr, err := org.ReadAuthToken(ctx, &authtokens.AuthToken{Id: authtoken.AuthTokenPrefix + "_doesntexis"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(apiErr.Status, http.StatusNotFound)

	_, apiErr, err = org.ReadAuthToken(ctx, &authtokens.AuthToken{Id: "invalid id"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(apiErr.Status, http.StatusBadRequest)
}
