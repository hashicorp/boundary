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

	// TODO: Delete

	// TODO: Error conditions once the proper errors are being returned.
	// Probably as parallel subtests against the same DB.
}
