package scopes_test

/*
func TestAuthenticate(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}
	ctx := context.Background()

	tok, apiErr, err := org.Authenticate(ctx, "am_1234567890", "admin", "hunter2")
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(tok)

	_, apiErr, err = org.Authenticate(ctx, "am_1234567890", "wrong", "wrong")
	assert.NoError(err)
	require.NotNil(t, apiErr)
	assert.EqualValuesf(http.StatusUnauthorized, apiErr.Status, "Expected unauthenticated, got %q", apiErr.Message)
}
*/
