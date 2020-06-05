package users_test

import (
	"net/http"
	"testing"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/api/users"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
)

func TestUser_Crud(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}

	checkUser := func(step string, hc *users.User, apiErr *api.Error, err error, wantedName string) {
		assert := assert.New(t)
		assert.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != nil {
			t.Errorf("ApiError message: %q", *apiErr.Message)
		}
		assert.NotNil(hc, "returned project", step)
		gotName := ""
		if hc.Name != nil {
			gotName = *hc.Name
		}
		assert.Equal(wantedName, gotName, step)
	}

	hc, apiErr, err := org.CreateUser(tc.Context(), &users.User{Name: api.String("foo")})
	checkUser("create", hc, apiErr, err, "foo")

	hc, apiErr, err = org.ReadUser(tc.Context(), &users.User{Id: hc.Id})
	checkUser("read", hc, apiErr, err, "foo")

	hc = &users.User{Id: hc.Id}
	hc.Name = api.String("bar")
	hc, apiErr, err = org.UpdateUser(tc.Context(), hc)
	checkUser("update", hc, apiErr, err, "bar")

	hc = &users.User{Id: hc.Id}
	hc.SetDefault("name")
	hc, apiErr, err = org.UpdateUser(tc.Context(), hc)
	checkUser("update", hc, apiErr, err, "")

	existed, apiErr, err := org.DeleteUser(tc.Context(), hc)
	assert.NoError(t, err)
	assert.True(t, existed, "Expected existing catalog when deleted, but it wasn't.")

	existed, apiErr, err = org.DeleteUser(tc.Context(), hc)
	assert.NoError(t, err)
	assert.False(t, existed, "Expected catalog to not exist when deleted, but it did.")
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
	p, apiErr, err := org.CreateProject(ctx, &scopes.Project{})
	assert.NoError(err)
	assert.NotNil(p)
	assert.Nil(apiErr)

	hc, apiErr, err := org.CreateUser(ctx, &users.User{})
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(hc)

	_, apiErr, err = org.CreateUser(ctx, &users.User{})
	assert.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = org.ReadUser(ctx, &users.User{Id: iam.UserPrefix + "_doesntexis"})
	assert.NoError(err)
	// TODO: Should this be nil instead of just a catalog that has no values set
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusNotFound)

	_, apiErr, err = org.ReadUser(ctx, &users.User{Id: "invalid id"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusBadRequest)

	_, apiErr, err = org.UpdateUser(ctx, &users.User{Id: hc.Id})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusBadRequest)
}
