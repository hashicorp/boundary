package scopes_test

/*
func TestProjects_List(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}
	ctx := context.Background()

	pl, apiErr, err := org.ListProjects(ctx)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.Empty(pl)

	var expected []*scopes.Project
	for i := 0; i < 10; i++ {
		expected = append(expected, &scopes.Project{Name: api.String(fmt.Sprint(i))})
	}

	expected[0], apiErr, err = org.CreateProject(ctx, expected[0])
	assert.NoError(err)
	assert.Nil(apiErr)

	pl, apiErr, err = org.ListProjects(ctx)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(pl))

	for i := 1; i < 10; i++ {
		expected[i], apiErr, err = org.CreateProject(ctx, expected[i])
		assert.NoError(err)
		assert.Nil(apiErr)
	}
	pl, apiErr, err = org.ListProjects(ctx)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(pl))
}

func comparableSlice(in []*scopes.Project) []scopes.Project {
	var filtered []scopes.Project
	for _, i := range in {
		p := scopes.Project{
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

func TestProjects_Crud(t *testing.T) {
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
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
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAuthorizationFailures: true})
	defer tc.Shutdown()
	ctx := tc.Context()

	client := tc.Client()
	org := &scopes.Org{
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
	assert.EqualValues(apiErr.Status, http.StatusNotFound)

	_, apiErr, err = org.ReadProject(ctx, &scopes.Project{Id: "invalid id"})
	assert.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(apiErr.Status, http.StatusBadRequest)
}
*/
