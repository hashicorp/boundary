package users_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/api/users"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
)

func TestUsers_List(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Organization{
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

func TestUser_Crud(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}

	checkUser := func(step string, u *users.User, apiErr *api.Error, err error, wantedName string) {
		assert := assert.New(t)
		assert.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != nil {
			t.Errorf("ApiError message: %q", *apiErr.Message)
		}
		assert.NotNil(u, "returned no resource", step)
		gotName := ""
		if u.Name != nil {
			gotName = *u.Name
		}
		assert.Equal(wantedName, gotName, step)
	}

	u, apiErr, err := org.CreateUser(tc.Context(), &users.User{Name: api.String("foo")})
	checkUser("create", u, apiErr, err, "foo")

	u, apiErr, err = org.ReadUser(tc.Context(), &users.User{Id: u.Id})
	checkUser("read", u, apiErr, err, "foo")

	u = &users.User{Id: u.Id}
	u.Name = api.String("bar")
	u, apiErr, err = org.UpdateUser(tc.Context(), u)
	checkUser("update", u, apiErr, err, "bar")

	u = &users.User{Id: u.Id}
	u.SetDefault("name")
	u, apiErr, err = org.UpdateUser(tc.Context(), u)
	checkUser("update", u, apiErr, err, "")

	existed, apiErr, err := org.DeleteUser(tc.Context(), u)
	assert.NoError(t, err)
	assert.True(t, existed, "Expected existing user when deleted, but it wasn't.")

	existed, apiErr, err = org.DeleteUser(tc.Context(), u)
	assert.NoError(t, err)
	assert.False(t, existed, "Expected user to not exist when deleted, but it did.")
}

func TestUser_Errors(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()
	ctx := tc.Context()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}

	u, apiErr, err := org.CreateUser(ctx, &users.User{Name: api.String("first")})
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(u)

	// Create another resource with the same name.
	_, apiErr, err = org.CreateUser(ctx, &users.User{Name: api.String("first")})
	assert.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = org.ReadUser(ctx, &users.User{Id: iam.UserPrefix + "_doesntexis"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusNotFound)

	_, apiErr, err = org.ReadUser(ctx, &users.User{Id: "invalid id"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusBadRequest)

	_, apiErr, err = org.UpdateUser(ctx, &users.User{Id: u.Id})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusBadRequest)
}
