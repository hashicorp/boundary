package users_test

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/api2/users"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/require"
)

/*
func TestUsers_List(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}
	ctx := context.Background()

	ul, apiErr, err := org.ListUsers(ctx)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(ul)

	var expected []*users.User
	for i := 0; i < 10; i++ {
		expected = append(expected, &users.User{Name: api.String(fmt.Sprint(i))})
	}

	expected[0], apiErr, err = org.CreateUser(ctx, expected[0])
	assert.NoError(err)
	assert.Nil(apiErr)

	ul, apiErr, err = org.ListUsers(ctx)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ul))

	for i := 1; i < 10; i++ {
		expected[i], apiErr, err = org.CreateUser(ctx, expected[i])
		assert.NoError(err)
		assert.Nil(apiErr)
	}
	ul, apiErr, err = org.ListUsers(ctx)
	require.NoError(t, err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ul))
}

func comparableSlice(in []*users.User) []users.User {
	var filtered []users.User
	for _, i := range in {
		p := users.User{
			Id:          i.Id,
			Name:        i.Name,
			Description: i.Description,
			CreatedTime: i.CreatedTime,
			UpdatedTime: i.UpdatedTime,
			Disabled:    i.Disabled,
		}
		filtered = append(filtered, p)
	}
	return filtered
}
*/

func TestUser_Crud(t *testing.T) {
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultOrgId:                 "o_1234567890",
	})
	defer tc.Shutdown()

	client := tc.Client()

	u := users.New(client)
	user, apiErr, err := u.Create(context.Background())
	require.NoError(t, err)
	require.Nil(t, apiErr)
	t.Logf("Got %v", user)
}
