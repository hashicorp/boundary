package scopes

import (
	"net/http"
	"testing"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
)

func TestProjects_Crud(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &Organization{
		Client: client,
	}

	checkProject := func(step string, p *Project, apiErr *api.Error, err error, wantedName string) {
		assert := assert.New(t)
		assert.NoError(err, step)
		assert.Nil(apiErr, step)
		assert.NotNil(p, "returned project", step)
		assert.Equal(wantedName, *p.Name, step)
	}

	p, apiErr, err := org.CreateProject(tc.Context(), &Project{Name: api.String("foo")})
	checkProject("create", p, apiErr, err, "foo")

	p, apiErr, err = org.ReadProject(tc.Context(), &Project{Id: p.Id})
	checkProject("read", p, apiErr, err, "foo")

	p = &Project{Id: p.Id}
	p.Name = api.String("bar")
	p, apiErr, err = org.UpdateProject(tc.Context(), p)
	checkProject("update", p, apiErr, err, "bar")

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
	org := &Organization{
		Client: client,
	}
	createdProj, apiErr, err := org.CreateProject(ctx, &Project{})
	assert.NoError(err)
	assert.NotNil(createdProj)
	assert.Nil(apiErr)

	_, apiErr, err = org.ReadProject(ctx, &Project{Id: "p_doesntexis"})
	assert.NoError(err)
	// TODO: Should this be nil instead of just a Project that has no values set
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusNotFound)

	_, apiErr, err = org.ReadProject(ctx, &Project{Id: "invalid id"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(*apiErr.Status, http.StatusBadRequest)
}
