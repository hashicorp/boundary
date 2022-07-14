package credentials_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	cs, err := credentialstores.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.NotNil(cs)

	credClient := credentials.NewClient(client)

	ul, err := credClient.List(tc.Context(), cs.Item.Id)
	require.NoError(err)
	assert.Empty(ul.Items)

	cred, err := credClient.Create(tc.Context(), credential.UsernamePasswordSubtype.String(), cs.Item.Id,
		credentials.WithName("0"),
		credentials.WithDescription("description"),
		credentials.WithUsernamePasswordCredentialUsername("user"),
		credentials.WithUsernamePasswordCredentialPassword("pass"))
	require.NoError(err)

	expected := make([]*credentials.Credential, 10)
	expected[0] = cred.Item

	ul, err = credClient.List(tc.Context(), cs.Item.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableCatalogSlice(expected[:1]), comparableCatalogSlice(ul.Items))

	for i := 1; i < 10; i++ {
		cred, err := credClient.Create(tc.Context(), credential.UsernamePasswordSubtype.String(), cs.Item.Id,
			credentials.WithName(fmt.Sprintf("%d", i)),
			credentials.WithDescription("description"),
			credentials.WithUsernamePasswordCredentialUsername("user"),
			credentials.WithUsernamePasswordCredentialPassword("pass"))
		require.NoError(err)
		expected[i] = cred.Item
	}
	ul, err = credClient.List(tc.Context(), cs.Item.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableCatalogSlice(expected), comparableCatalogSlice(ul.Items))

	filterItem := ul.Items[3]
	ul, err = credClient.List(tc.Context(), cs.Item.Id,
		credentials.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)
}

func comparableCatalogSlice(in []*credentials.Credential) []credentials.Credential {
	var filtered []credentials.Credential
	for _, i := range in {
		p := credentials.Credential{
			Id:          i.Id,
			Name:        i.Name,
			Description: i.Description,
			CreatedTime: i.CreatedTime,
			UpdatedTime: i.UpdatedTime,
			Attributes:  i.Attributes,
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func TestCrud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	cs, err := credentialstores.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.NotNil(cs)

	checkResource := func(step string, c *credentials.Credential, wantedName, wantedUser string, wantVersion uint32) {
		assert.NotNil(c, "returned no resource", step)
		assert.Equal(wantedName, c.Name, step)
		gotUser, ok := c.Attributes["username"]
		require.True(ok)
		assert.Equal(wantedUser, gotUser, step)
		assert.Equal(wantVersion, c.Version)
	}
	credClient := credentials.NewClient(client)

	cred, err := credClient.Create(tc.Context(), credential.UsernamePasswordSubtype.String(), cs.Item.Id, credentials.WithName("foo"),
		credentials.WithUsernamePasswordCredentialUsername("user"), credentials.WithUsernamePasswordCredentialPassword("pass"))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("create", cred.Item, "foo", "user", 1)

	cred, err = credClient.Read(tc.Context(), cred.Item.Id)
	require.NoError(err)
	require.NotNil(cs)
	checkResource("read", cred.Item, "foo", "user", 1)

	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version, credentials.WithName("bar"))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("update", cred.Item, "bar", "user", 2)

	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version, credentials.WithUsernamePasswordCredentialUsername("newuser"))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("update", cred.Item, "bar", "newuser", 3)

	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version, credentials.DefaultName())
	require.NoError(err)
	require.NotNil(cs)
	checkResource("update", cred.Item, "", "newuser", 4)

	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version,
		credentials.WithName("newuser"), credentials.WithUsernamePasswordCredentialUsername("neweruser"))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("update", cred.Item, "newuser", "neweruser", 5)

	_, err = credClient.Delete(tc.Context(), cred.Item.Id)
	assert.NoError(err)

	_, err = credClient.Delete(tc.Context(), cred.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	cs, err := credentialstores.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.NotNil(cs)

	c := credentials.NewClient(client)

	cred, err := c.Create(tc.Context(), credential.UsernamePasswordSubtype.String(), cs.Item.Id, credentials.WithName("foo"),
		credentials.WithUsernamePasswordCredentialUsername("user"), credentials.WithUsernamePasswordCredentialPassword("pass"))
	require.NoError(err)
	require.NotNil(cred)

	// A malformed id is processed as the id and not a different path to the api.
	_, err = c.Read(tc.Context(), fmt.Sprintf("%s/../", cred.Item.Id))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
	require.Len(apiErr.Details.RequestFields, 1)
	assert.Equal(apiErr.Details.RequestFields[0].Name, "id")

	// Updating the wrong version should fail.
	_, err = c.Update(tc.Context(), cred.Item.Id, 73, credentials.WithName("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Same name
	_, err = c.Create(tc.Context(), credential.UsernamePasswordSubtype.String(), proj.GetPublicId(), credentials.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)

	_, err = c.Read(tc.Context(), credential.UsernamePasswordCredentialPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = c.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
