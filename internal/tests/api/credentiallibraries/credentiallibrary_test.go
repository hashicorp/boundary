// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentiallibraries_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	vaultServ := vault.NewTestVaultServer(t)
	_, vaultTok := vaultServ.CreateToken(t)

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	cs, err := credentialstores.NewClient(client).Create(tc.Context(), "vault", proj.GetPublicId(),
		credentialstores.WithVaultCredentialStoreAddress(vaultServ.Addr), credentialstores.WithVaultCredentialStoreToken(vaultTok))
	require.NoError(err)
	require.NotNil(cs)

	lClient := credentiallibraries.NewClient(client)

	ul, err := lClient.List(tc.Context(), cs.Item.Id)
	require.NoError(err)
	assert.Empty(ul.Items)

	var expected []*credentiallibraries.CredentialLibrary
	for i := 0; i < 10; i++ {
		expected = append(expected, &credentiallibraries.CredentialLibrary{Name: fmt.Sprint(i), Attributes: map[string]any{"vault_path": "something"}})
	}

	cl, err := lClient.Create(tc.Context(), "vault-generic", cs.Item.Id, credentiallibraries.WithName(expected[0].Name), credentiallibraries.WithVaultCredentialLibraryPath("something"))
	require.NoError(err)
	expected[0] = cl.Item

	ul, err = lClient.List(tc.Context(), cs.Item.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableSetSlice(expected[:1]), comparableSetSlice(ul.Items))

	for i := 1; i < 10; i++ {
		cl, err = lClient.Create(tc.Context(), "vault-generic", cs.Item.Id, credentiallibraries.WithName(expected[i].Name), credentiallibraries.WithVaultCredentialLibraryPath("something"))
		require.NoError(err)
		expected[i] = cl.Item
	}
	ul, err = lClient.List(tc.Context(), cs.Item.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableSetSlice(expected), comparableSetSlice(ul.Items))

	filterItem := ul.Items[3]
	ul, err = lClient.List(tc.Context(), cs.Item.Id,
		credentiallibraries.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)
}

func comparableSetSlice(in []*credentiallibraries.CredentialLibrary) []credentiallibraries.CredentialLibrary {
	var filtered []credentiallibraries.CredentialLibrary
	for _, i := range in {
		p := credentiallibraries.CredentialLibrary{
			Id:          i.Id,
			Name:        i.Name,
			Description: i.Description,
			CreatedTime: i.CreatedTime,
			UpdatedTime: i.UpdatedTime,
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

	cs, err := credentialstores.NewClient(client).Create(tc.Context(), "vault", proj.GetPublicId(),
		credentialstores.WithVaultCredentialStoreAddress(vaultServ.Addr), credentialstores.WithVaultCredentialStoreToken(vaultTok))
	require.NoError(err)
	require.NotNil(cs)

	checkResource := func(t *testing.T, step string, r *credentiallibraries.CredentialLibrary, err error, wantedName string, wantVersion uint32) {
		t.Helper()
		require.NoError(err, step)
		assert.NotNil(r, "returned no resource", step)
		gotName := ""
		if r.Name != "" {
			gotName = r.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, r.Version)
	}

	lClient := credentiallibraries.NewClient(client)

	r, err := lClient.Create(tc.Context(), "vault-generic", cs.Item.Id, credentiallibraries.WithName("foo"),
		credentiallibraries.WithVaultCredentialLibraryPath("something"))
	require.Nil(err)
	checkResource(t, "create", r.Item, err, "foo", 1)

	r, err = lClient.Read(tc.Context(), r.Item.Id)
	checkResource(t, "read", r.Item, err, "foo", 1)

	r, err = lClient.Update(tc.Context(), r.Item.Id, r.Item.Version, credentiallibraries.WithName("bar"))
	checkResource(t, "update", r.Item, err, "bar", 2)

	r, err = lClient.Update(tc.Context(), r.Item.Id, r.Item.Version, credentiallibraries.DefaultName())
	checkResource(t, "update", r.Item, err, "", 3)

	_, err = lClient.Delete(tc.Context(), r.Item.Id)
	assert.NoError(err)
	_, err = lClient.Delete(tc.Context(), r.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
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

	cs, err := credentialstores.NewClient(client).Create(tc.Context(), "vault", proj.GetPublicId(),
		credentialstores.WithVaultCredentialStoreAddress(vaultServ.Addr), credentialstores.WithVaultCredentialStoreToken(vaultTok))
	require.NoError(err)
	require.NotNil(cs)

	lClient := credentiallibraries.NewClient(client)

	l, err := lClient.Create(tc.Context(), "vault-generic", cs.Item.Id, credentiallibraries.WithName("foo"),
		credentiallibraries.WithVaultCredentialLibraryPath("something"))
	require.NoError(err)
	assert.NotNil(l)

	// A malformed id is processed as the id and not a different path to the api.
	_, err = lClient.Read(tc.Context(), fmt.Sprintf("%s/../", l.Item.Id))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
	require.Len(apiErr.Details.RequestFields, 1)
	assert.Equal(apiErr.Details.RequestFields[0].Name, "id")

	// Updating the wrong version should fail.
	_, err = lClient.Update(tc.Context(), l.Item.Id, 73, credentiallibraries.WithName("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	l, err = lClient.Create(tc.Context(), cs.Item.Type, cs.Item.Id, credentiallibraries.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.Nil(l)

	_, err = lClient.Read(tc.Context(), globals.VaultCredentialLibraryPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = lClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
