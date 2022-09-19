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
	"golang.org/x/crypto/ssh/testdata"
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

func TestCrudSpk(t *testing.T) {
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

	spk := string(testdata.PEMBytes["rsa"])
	spkWithPass := string(testdata.PEMEncryptedKeys[0].PEMBytes)
	pass := testdata.PEMEncryptedKeys[0].EncryptionKey

	cred, err := credClient.Create(tc.Context(), credential.SshPrivateKeySubtype.String(), cs.Item.Id, credentials.WithName("foo"),
		credentials.WithSshPrivateKeyCredentialUsername("user"),
		credentials.WithSshPrivateKeyCredentialPrivateKey(spkWithPass),
		credentials.WithSshPrivateKeyCredentialPrivateKeyPassphrase(pass))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("create", cred.Item, "foo", "user", 1)

	// Validate passphrase hmac was set and passpharse is not set
	passHmac, ok := cred.GetItem().Attributes["private_key_passphrase_hmac"].(string)
	require.True(ok)
	require.NotNil(passHmac)

	cred, err = credClient.Read(tc.Context(), cred.Item.Id)
	require.NoError(err)
	require.NotNil(cs)
	checkResource("read", cred.Item, "foo", "user", 1)

	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version, credentials.WithName("bar"))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("update", cred.Item, "bar", "user", 2)

	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version, credentials.WithSshPrivateKeyCredentialUsername("newuser"))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("update", cred.Item, "bar", "newuser", 3)

	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version, credentials.DefaultName())
	require.NoError(err)
	require.NotNil(cs)
	checkResource("update", cred.Item, "", "newuser", 4)

	// Update to non-encrypted key
	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version, credentials.WithSshPrivateKeyCredentialPrivateKey(spk))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("update", cred.Item, "", "newuser", 5)

	// Validate passphrase hmac is no longer set
	_, ok = cred.GetItem().Attributes["private_key_passphrase_hmac"].(string)
	require.False(ok)

	_, err = credClient.Delete(tc.Context(), cred.Item.Id)
	assert.NoError(err)

	_, err = credClient.Delete(tc.Context(), cred.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
}

func TestCrudJson(t *testing.T) {
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

	checkResource := func(step string, c *credentials.Credential, wantedName string, wantVersion uint32) {
		assert.NotNil(c, "returned no resource", step)
		assert.Equal(wantedName, c.Name, step)
		assert.Equal(wantVersion, c.Version)
	}
	credClient := credentials.NewClient(client)

	obj := map[string]interface{}{
		"username": "admin",
		"password": "pass",
	}
	cred, err := credClient.Create(tc.Context(), credential.JsonSubtype.String(), cs.Item.Id, credentials.WithName("foo"), credentials.WithJsonCredentialObject(obj))
	require.NoError(err)
	require.NotNil(cred)
	checkResource("create", cred.Item, "foo", 1)

	jsonAttributes, err := cred.GetItem().GetJsonAttributes()
	require.NoError(err)
	require.Nil(jsonAttributes.Object)
	require.NotEmpty(jsonAttributes.ObjectHmac)

	sshAttributes, err := cred.GetItem().GetSshPrivateKeyAttributes()
	require.Error(err)
	require.Nil(sshAttributes)

	upAttributes, err := cred.GetItem().GetUsernamePasswordAttributes()
	require.Error(err)
	require.Nil(upAttributes)

	// Validate object hmac was set and object is not set
	originalObjectHmac, ok := cred.GetItem().Attributes["object_hmac"].(string)
	require.True(ok)
	require.NotNil(originalObjectHmac)
	object, ok := cred.GetItem().Attributes["object"].(string)
	require.False(ok)
	require.Empty(object)

	cred, err = credClient.Read(tc.Context(), cred.Item.Id)
	require.NoError(err)
	require.NotNil(cs)
	checkResource("read", cred.Item, "foo", 1)

	// Validate object hmac was set and object is not set
	objectHmac, ok := cred.GetItem().Attributes["object_hmac"].(string)
	require.True(ok)
	require.NotNil(objectHmac)
	object, ok = cred.GetItem().Attributes["object"].(string)
	require.False(ok)
	require.Empty(object)

	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version, credentials.WithName("bar"))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("update", cred.Item, "bar", 2)

	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version, credentials.WithJsonCredentialObject(map[string]interface{}{
		"username": "not_admin",
		"password": "not_password",
	}))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("update", cred.Item, "bar", 3)

	// Validate secret hmac was set & is not the same as the original value & secret is not set
	objectHmac, ok = cred.GetItem().Attributes["object_hmac"].(string)
	require.True(ok)
	require.NotNil(objectHmac)
	require.NotEqual(originalObjectHmac, objectHmac)
	object, ok = cred.GetItem().Attributes["secrets"].(string)
	require.False(ok)
	require.Empty(object)

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
