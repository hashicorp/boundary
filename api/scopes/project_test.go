package scopes_test

import (
	"net/http"
	"testing"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
)

func TestProjects_Crud(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}

	checkProject := func(step string, p *scopes.Project, apiErr *api.Error, err error, wantedName string) {
		assert := assert.New(t)
		assert.NoError(err, step)
		assert.Nil(apiErr, step)
		assert.NotNil(p, "returned project", step)
		gotName := ""
		if p.Name != nil {
			gotName = *p.Name
		}
		assert.Equal(wantedName, gotName, step)
	}

	p, apiErr, err := org.CreateProject(tc.Context(), &scopes.Project{Name: api.String("foo")})
	checkProject("create", p, apiErr, err, "foo")

	p, apiErr, err = org.ReadProject(tc.Context(), &scopes.Project{Id: p.Id})
	checkProject("read", p, apiErr, err, "foo")

	p = &scopes.Project{Id: p.Id}
	p.Name = api.String("bar")
	p, apiErr, err = org.UpdateProject(tc.Context(), p)
	checkProject("update", p, apiErr, err, "bar")

	p = &scopes.Project{Id: p.Id}
	p.SetDefault("name")
	p, apiErr, err = org.UpdateProject(tc.Context(), p)
	checkProject("update, unset name", p, apiErr, err, "")

	existed, apiErr, err := org.DeleteProject(tc.Context(), p)
	assert.NoError(t, err)
	assert.True(t, existed, "Expected existing project when deleted, but it wasn't.")

	existed, apiErr, err = org.DeleteProject(tc.Context(), p)
	assert.NoError(t, err)
	assert.False(t, existed, "Expected project to not exist when deleted, but it did.")
}

// TODO: Get better coverage for expected errors and error formats.
func TestProject_Errors(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()
	ctx := tc.Context()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}
	createdProj, apiErr, err := org.CreateProject(ctx, &scopes.Project{})
	assert.NoError(err)
	assert.NotNil(createdProj)
	assert.Nil(apiErr)

	_, apiErr, err = org.ReadProject(ctx, &scopes.Project{Id: "p_doesntexis"})
	assert.NoError(err)
	// TODO: Should this be nil instead of just a Project that has no values set
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusNotFound)

	_, apiErr, err = org.ReadProject(ctx, &scopes.Project{Id: "invalid id"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusBadRequest)
}
