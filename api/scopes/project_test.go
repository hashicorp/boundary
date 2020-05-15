package scopes

import (
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

	name := "foo"

	checkProject := func(step string, p *Project, apiErr *api.Error, err error) {
		assert := assert.New(t)
		assert.NoError(err, step)
		assert.Nil(apiErr, step)
		assert.NotNil(p, "returned project", step)
		assert.NotNil(p, "returned project name", step)
		assert.Equal(name, *p.Name, step)
	}

	p, apiErr, err := org.CreateProject(tc.Context(), &Project{Name: api.String(name)})
	checkProject("create", p, apiErr, err)

	p, apiErr, err = org.ReadProject(tc.Context(), &Project{Id: p.Id})
	checkProject("read", p, apiErr, err)

	// TODO: Update and Delete
	p, apiErr, err = org.UpdateProject(tc.Context(), &Project{Id: p.Id})
	checkProject("read", p, apiErr, err)

	// TODO: Error conditions once the proper errors are being returned.
	// Probably as parallel subtests against the same DB.
}
