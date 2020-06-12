package groups_test

import (
	"net/http"
	"testing"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/groups"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
)

func TestGroup_Crud(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}

	checkGroup := func(step string, g *groups.Group, apiErr *api.Error, err error, wantedName string) {
		assert := assert.New(t)
		assert.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != nil {
			t.Errorf("ApiError message: %q", *apiErr.Message)
		}
		assert.NotNil(g, "returned no resource", step)
		gotName := ""
		if g.Name != nil {
			gotName = *g.Name
		}
		assert.Equal(wantedName, gotName, step)
	}

	g, apiErr, err := org.CreateGroup(tc.Context(), &groups.Group{Name: api.String("foo")})
	checkGroup("create", g, apiErr, err, "foo")

	g, apiErr, err = org.ReadGroup(tc.Context(), &groups.Group{Id: g.Id})
	checkGroup("read", g, apiErr, err, "foo")

	g = &groups.Group{Id: g.Id}
	g.Name = api.String("bar")
	g, apiErr, err = org.UpdateGroup(tc.Context(), g)
	checkGroup("update", g, apiErr, err, "bar")

	g = &groups.Group{Id: g.Id}
	g.SetDefault("name")
	g, apiErr, err = org.UpdateGroup(tc.Context(), g)
	checkGroup("update", g, apiErr, err, "")

	existed, apiErr, err := org.DeleteGroup(tc.Context(), g)
	assert.NoError(t, err)
	assert.True(t, existed, "Expected existing user when deleted, but it wasn't.")

	existed, apiErr, err = org.DeleteGroup(tc.Context(), g)
	assert.NoError(t, err)
	assert.False(t, existed, "Expected user to not exist when deleted, but it did.")
}

func TestGroup_Errors(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()
	ctx := tc.Context()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}

	u, apiErr, err := org.CreateGroup(ctx, &groups.Group{Name: api.String("first")})
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(u)

	// Create another resource with the same name.
	_, apiErr, err = org.CreateGroup(ctx, &groups.Group{Name: api.String("first")})
	assert.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = org.ReadGroup(ctx, &groups.Group{Id: iam.GroupPrefix + "_doesntexis"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusNotFound)

	_, apiErr, err = org.ReadGroup(ctx, &groups.Group{Id: "invalid id"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusBadRequest)

	_, apiErr, err = org.UpdateGroup(ctx, &groups.Group{Id: u.Id})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusBadRequest)
}
