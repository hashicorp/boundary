package credentialstores_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	vaultServ := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestNoTLS))

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	storeClient := credentialstores.NewClient(client)

	ul, err := storeClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.Empty(ul.Items)

	var expected []*credentialstores.CredentialStore
	for i := 0; i < 10; i++ {
		_, tok := vaultServ.CreateToken(t)
		expected = append(expected, &credentialstores.CredentialStore{Name: fmt.Sprint(i), Attributes: map[string]interface{}{
			"address": vaultServ.Addr,
			"token":   tok,
		}})
	}

	cr, err := storeClient.Create(tc.Context(), "vault", proj.GetPublicId(), credentialstores.WithName(expected[0].Name),
		credentialstores.WithVaultCredentialStoreAddress(vaultServ.Addr), credentialstores.WithVaultCredentialStoreToken(expected[0].Attributes["token"].(string)))
	require.NoError(err)
	expected[0] = cr.Item

	ul, err = storeClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableCatalogSlice(expected[:1]), comparableCatalogSlice(ul.Items))

	for i := 1; i < 10; i++ {
		cr, err = storeClient.Create(tc.Context(), "vault", proj.GetPublicId(), credentialstores.WithName(expected[i].Name),
			credentialstores.WithVaultCredentialStoreAddress(vaultServ.Addr), credentialstores.WithVaultCredentialStoreToken(expected[i].Attributes["token"].(string)))
		require.NoError(err)
		expected[i] = cr.Item
	}
	ul, err = storeClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableCatalogSlice(expected), comparableCatalogSlice(ul.Items))

	filterItem := ul.Items[3]
	ul, err = storeClient.List(tc.Context(), proj.GetPublicId(),
		credentialstores.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)
}

func comparableCatalogSlice(in []*credentialstores.CredentialStore) []credentialstores.CredentialStore {
	var filtered []credentialstores.CredentialStore
	for _, i := range in {
		p := credentialstores.CredentialStore{
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
	vaultServ := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestNoTLS))
	_, vaultTok := vaultServ.CreateToken(t)

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	checkResource := func(step string, cs *credentialstores.CredentialStore, err error, wantedName string, wantVersion uint32) {
		assert.NotNil(cs, "returned no resource", step)
		gotName := ""
		if cs.Name != "" {
			gotName = cs.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, cs.Version)
	}

	csClient := credentialstores.NewClient(client)

	cs, err := csClient.Create(tc.Context(), "vault", proj.GetPublicId(), credentialstores.WithName("foo"),
		credentialstores.WithVaultCredentialStoreAddress(vaultServ.Addr), credentialstores.WithVaultCredentialStoreToken(vaultTok))
	require.NoError(err)
	require.NotNil(cs)
	checkResource("create", cs.Item, err, "foo", 1)

	cs, err = csClient.Read(tc.Context(), cs.Item.Id)
	checkResource("read", cs.Item, err, "foo", 1)

	cs, err = csClient.Update(tc.Context(), cs.Item.Id, cs.Item.Version, credentialstores.WithName("bar"))
	checkResource("update", cs.Item, err, "bar", 2)

	cs, err = csClient.Update(tc.Context(), cs.Item.Id, cs.Item.Version, credentialstores.DefaultName())
	checkResource("update", cs.Item, err, "", 3)

	_, err = csClient.Delete(tc.Context(), cs.Item.Id)
	assert.NoError(err)

	_, err = csClient.Delete(tc.Context(), cs.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	vaultServ := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestNoTLS))
	_, vaultTok := vaultServ.CreateToken(t)

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	c := credentialstores.NewClient(client)

	vs, err := c.Create(tc.Context(), "vault", proj.GetPublicId(), credentialstores.WithName("foo"),
		credentialstores.WithVaultCredentialStoreAddress(vaultServ.Addr), credentialstores.WithVaultCredentialStoreToken(vaultTok))
	require.NoError(err)
	apiErr := api.AsServerError(err)
	assert.Nil(apiErr)
	assert.NotNil(vs)

	// Updating the wrong version should fail.
	_, err = c.Update(tc.Context(), vs.Item.Id, 73, credentialstores.WithName("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// same token
	_, err = c.Create(tc.Context(), "vault", proj.GetPublicId(),
		credentialstores.WithVaultCredentialStoreAddress(vaultServ.Addr), credentialstores.WithVaultCredentialStoreToken(vaultTok))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)

	// Same name
	_, err = c.Create(tc.Context(), "vault", proj.GetPublicId(), credentialstores.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)

	_, err = c.Read(tc.Context(), vault.CredentialStorePrefix+"_doesntexis")
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
