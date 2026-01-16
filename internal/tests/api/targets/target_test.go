// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package targets_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	aliastar "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

func TestHostSetASD(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	token := tc.Token()
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	client := tc.Client().Clone()
	client.SetToken(token.Token)

	hc, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)

	hSetClient := hostsets.NewClient(client)
	hSet, err := hSetClient.Create(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.NotNil(hSet)
	hSet2, err := hSetClient.Create(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.NotNil(hSet2)

	tarClient := targets.NewClient(client)
	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)
	require.NotNil(tar)
	assert.Empty(tar.Item.HostSourceIds)

	aliasedTar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("aliased"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)
	require.NotNil(aliasedTar)
	assert.Empty(aliasedTar.Item.HostSourceIds)

	rw := db.New(tc.DbConn())
	al := aliastar.TestAlias(t, rw, "alias.value", aliastar.WithDestinationId(aliasedTar.Item.Id))

	cases := []struct {
		name string
		id   string
	}{
		{
			name: "target id",
			id:   tar.Item.Id,
		},
		{
			name: "aliases",
			id:   al.GetValue(),
		},
	}

	for _, c := range cases {
		tar, err := tarClient.AddHostSources(tc.Context(), c.id, 1, []string{hSet.Item.Id})
		require.NoError(err)
		require.NotNil(tar)
		assert.ElementsMatch(tar.Item.HostSourceIds, []string{hSet.Item.Id})

		tar, err = tarClient.SetHostSources(tc.Context(), c.id, tar.Item.Version, []string{hSet2.Item.Id})
		require.NoError(err)
		require.NotNil(tar)
		assert.ElementsMatch(tar.Item.HostSourceIds, []string{hSet2.Item.Id})

		tar, err = tarClient.RemoveHostSources(tc.Context(), c.id, tar.Item.Version, []string{hSet2.Item.Id})
		require.NoError(err)
		require.NotNil(tar)
		assert.Empty(tar.Item.HostSourceIds)
	}
}

func TestCredentialSourcesASD(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()
	vaultServ := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestNoTLS))
	_, vaultTok := vaultServ.CreateToken(t)

	token := tc.Token()
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	client := tc.Client().Clone()
	client.SetToken(token.Token)

	csVault, err := credentialstores.NewClient(client).Create(tc.Context(), "vault", proj.GetPublicId(),
		credentialstores.WithVaultCredentialStoreAddress(vaultServ.Addr), credentialstores.WithVaultCredentialStoreToken(vaultTok))
	require.NoError(err)
	require.NotNil(csVault)

	lClient := credentiallibraries.NewClient(client)
	lib1, err := lClient.Create(tc.Context(), "vault-generic", csVault.Item.Id, credentiallibraries.WithVaultCredentialLibraryPath("something1"))
	require.NoError(err)
	require.NotNil(lib1)

	lib2, err := lClient.Create(tc.Context(), "vault-generic", csVault.Item.Id, credentiallibraries.WithVaultCredentialLibraryPath("something2"))
	require.NoError(err)
	require.NotNil(lib2)

	csStatic, err := credentialstores.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	require.NotNil(csStatic)

	cClient := credentials.NewClient(client)
	cOpts := []credentials.Option{credentials.WithUsernamePasswordCredentialUsername("user"), credentials.WithUsernamePasswordCredentialPassword("pass")}
	cred, err := cClient.Create(tc.Context(), "username_password", csStatic.Item.Id, cOpts...)
	require.NoError(err)
	require.NotNil(cred)

	tarClient := targets.NewClient(client)
	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)
	require.NotNil(tar)
	assert.Empty(tar.Item.BrokeredCredentialSourceIds)

	aliasedTar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("aliased"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)
	require.NotNil(aliasedTar)
	assert.Empty(aliasedTar.Item.BrokeredCredentialSourceIds)

	rw := db.New(tc.DbConn())
	al := aliastar.TestAlias(t, rw, "alias.value", aliastar.WithDestinationId(aliasedTar.Item.Id))

	cases := []struct {
		name string
		id   string
	}{
		{
			name: "target id",
			id:   tar.Item.Id,
		},
		{
			name: "aliases",
			id:   al.GetValue(),
		},
	}

	for _, c := range cases {
		// Add first Vault library
		tar, err := tarClient.AddCredentialSources(tc.Context(), c.id, 1,
			targets.WithBrokeredCredentialSourceIds([]string{lib1.Item.Id}))
		require.NoError(err)
		require.NotNil(tar)
		assert.ElementsMatch(tar.Item.BrokeredCredentialSourceIds, []string{lib1.Item.Id})
		assert.ElementsMatch(tar.Item.BrokeredCredentialSources, []*targets.CredentialSource{
			{
				Id:                lib1.Item.Id,
				CredentialStoreId: csVault.Item.Id,
			},
		})

		// Set second Vault library and a static credential
		tar, err = tarClient.SetCredentialSources(tc.Context(), c.id, tar.Item.Version,
			targets.WithBrokeredCredentialSourceIds([]string{lib2.Item.Id, cred.Item.Id}))
		require.NoError(err)
		require.NotNil(tar)
		assert.ElementsMatch(tar.Item.BrokeredCredentialSourceIds, []string{lib2.Item.Id, cred.Item.Id})
		assert.ElementsMatch(tar.Item.BrokeredCredentialSources, []*targets.CredentialSource{
			{
				Id:                lib2.Item.Id,
				CredentialStoreId: csVault.Item.Id,
			},
			{
				Id:                cred.Item.Id,
				CredentialStoreId: csStatic.Item.Id,
			},
		})
		// Remove second Vault library
		tar, err = tarClient.RemoveCredentialSources(tc.Context(), c.id, tar.Item.Version,
			targets.WithBrokeredCredentialSourceIds([]string{lib2.Item.Id}))
		require.NoError(err)
		require.NotNil(tar)
		assert.ElementsMatch(tar.Item.BrokeredCredentialSourceIds, []string{cred.Item.Id})
		assert.ElementsMatch(tar.Item.BrokeredCredentialSources, []*targets.CredentialSource{
			{
				Id:                cred.Item.Id,
				CredentialStoreId: csStatic.Item.Id,
			},
		})

		// Set empty credential sources
		tar, err = tarClient.SetCredentialSources(tc.Context(), c.id, tar.Item.Version,
			targets.WithBrokeredCredentialSourceIds([]string{}))
		require.NoError(err)
		require.NotNil(tar)
		assert.Empty(tar.Item.BrokeredCredentialSourceIds)
	}
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	// Add unpriv user to default role in new project. Also add create grant as
	// it will be needed later in the test and no-op for listing visibility.
	rls, err := roles.NewClient(client).List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	var defaultRoleId string
	for _, rl := range rls.Items {
		if strings.Contains(rl.Name, "Default") {
			defaultRoleId = rl.Id
			break
		}
	}
	require.NotEmpty(defaultRoleId)
	unprivToken := tc.UnprivilegedToken()
	iam.TestUserRole(t, tc.DbConn(), defaultRoleId, unprivToken.UserId)
	iam.TestRoleGrant(t, tc.DbConn(), defaultRoleId, "type=target;actions=create")
	iam.TestRoleGrant(t, tc.DbConn(), defaultRoleId, "ids=*;type=target;actions=no-op")

	client.SetToken(unprivToken.Token)
	tarClient := targets.NewClient(client)
	ul, err := tarClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.Empty(ul.Items)

	var expected []*targets.Target
	for i := 0; i < 10; i++ {
		expected = append(expected, &targets.Target{Name: fmt.Sprint(i)})
	}

	tcr, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName(expected[0].Name), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)
	expected[0] = tcr.Item

	ul, err = tarClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ul.Items))

	for i := 1; i < 10; i++ {
		tcr, err = tarClient.Create(
			tc.Context(),
			"tcp",
			proj.GetPublicId(),
			targets.WithName(expected[i].Name),
			targets.WithTcpTargetDefaultPort(uint32(i)),
			targets.WithTcpTargetDefaultClientPort(uint32(i+100)),
		)
		require.NoError(err)
		expected[i] = tcr.Item
	}
	filterItem := expected[3]
	ul, err = tarClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ul.Items))

	ul, err = tarClient.List(tc.Context(), proj.GetPublicId(),
		targets.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)

	filterstr := fmt.Sprintf(`"/item/attributes/default_port"==%d`, uint32(filterItem.Attributes["default_port"].(float64)))
	ul, err = tarClient.List(tc.Context(), proj.GetPublicId(),
		targets.WithFilter(filterstr))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)
}

func TestListWithListToken(t *testing.T) {
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	require := require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)
	_, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("1"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)
	_, err = tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("2"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)

	// Refresh tokens using project scope
	res, err := tarClient.List(tc.Context(), proj.GetPublicId(), targets.WithRecursive(true))
	require.NoError(err)
	require.Len(res.Items, 2, "expected the 2 targets created above")
	refTok := res.ListToken

	res, err = tarClient.List(tc.Context(), proj.GetPublicId(), targets.WithRecursive(true), targets.WithListToken(refTok))
	require.NoError(err)
	require.Empty(res.Items)

	// Refresh tokens recursive listing over global scope
	res, err = tarClient.List(tc.Context(), "global", targets.WithRecursive(true))
	require.NoError(err)
	require.Len(res.Items, 4, "expected the 2 targets created above and the 2 auto created for the test controller")
	refTok = res.ListToken

	res, err = tarClient.List(tc.Context(), "global", targets.WithRecursive(true), targets.WithListToken(refTok))
	require.NoError(err)
	require.Empty(res.Items)
}

func TestListWithPageSize(t *testing.T) {
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	require := require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)
	_, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("1"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)
	_, err = tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("2"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)

	// Refresh tokens recursive listing over global scope
	res, err := tarClient.List(tc.Context(), "global", targets.WithRecursive(true), targets.WithPageSize(2))
	require.NoError(err)
	require.Len(res.Items, 4, "expected the 2 targets created above and the 2 auto created for the test controller")
	refTok := res.ListToken

	res, err = tarClient.List(tc.Context(), "global", targets.WithRecursive(true), targets.WithListToken(refTok))
	require.NoError(err)
	require.Empty(res.Items)
}

func TestTarget_AddressMutualExclusiveRelationship(t *testing.T) {
	tc := controller.NewTestController(t, nil)

	client := tc.Client()
	at := tc.Token()
	client.SetToken(at.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(at.UserId))
	tClient := targets.NewClient(client)

	// Create target with a network address association
	targetResp, err := tClient.Create(tc.Context(), "tcp", proj.GetPublicId(),
		targets.WithName("test-address"), targets.WithAddress("::1"), targets.WithTcpTargetDefaultPort(22))
	require.NoError(t, err)
	require.NotNil(t, targetResp)
	require.Equal(t, "::1", targetResp.GetItem().Address)

	// Setup host catalog, host set, & host resources
	hc, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(t, err)
	require.NotNil(t, hc)
	hs, err := hostsets.NewClient(client).Create(tc.Context(), hc.Item.Id)
	require.NoError(t, err)
	require.NotNil(t, hs)
	h, err := hosts.NewClient(client).Create(tc.Context(), hc.Item.Id, hosts.WithStaticHostAddress("::1"))
	require.NoError(t, err)
	require.NotNil(t, h)
	hUpdate, err := hostsets.NewClient(client).AddHosts(tc.Context(), hs.Item.Id, hs.Item.Version, []string{h.GetItem().Id})
	require.NoError(t, err)
	require.NotNil(t, hUpdate)

	// Expect error when associating a host source to the target with a direct network address association
	targetId := targetResp.GetItem().Id
	version := targetResp.GetItem().Version
	updateResp, err := tClient.AddHostSources(tc.Context(), targetId, version, []string{hs.Item.Id})
	require.Error(t, err)
	require.Nil(t, updateResp)
	apiErr := api.AsServerError(err)
	require.NotNil(t, apiErr)
	require.Equal(t, http.StatusBadRequest, apiErr.Response().StatusCode())

	// Remove direct network address association. Successfully add a host source to target.
	targetResp, err = tClient.Update(tc.Context(), targetId, version, targets.DefaultAddress())
	require.NoError(t, err)
	require.NotNil(t, targetResp)
	require.Empty(t, targetResp.GetItem().Address)
	version = targetResp.GetItem().Version
	updateResp, err = tClient.AddHostSources(tc.Context(), targetId, version, []string{hs.Item.Id})
	require.NoError(t, err)
	require.NotNil(t, updateResp)
	require.Empty(t, updateResp.GetItem().Address)
	require.Equal(t, []string{hs.Item.Id}, updateResp.GetItem().HostSourceIds)
}

func TestTarget_HostSourceMutualExclusiveRelationship(t *testing.T) {
	tc := controller.NewTestController(t, nil)

	client := tc.Client()
	at := tc.Token()
	client.SetToken(at.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(at.UserId))
	tClient := targets.NewClient(client)

	// Setup host catalog, host set, & host resources
	hc, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(t, err)
	require.NotNil(t, hc)
	hs, err := hostsets.NewClient(client).Create(tc.Context(), hc.Item.Id)
	require.NoError(t, err)
	require.NotNil(t, hs)
	h, err := hosts.NewClient(client).Create(tc.Context(), hc.Item.Id, hosts.WithStaticHostAddress("::1"))
	require.NoError(t, err)
	require.NotNil(t, h)
	hUpdate, err := hostsets.NewClient(client).AddHosts(tc.Context(), hs.Item.Id, hs.Item.Version, []string{h.GetItem().Id})
	require.NoError(t, err)
	require.NotNil(t, hUpdate)

	// Create target without a network address association
	targetResp, err := tClient.Create(tc.Context(), "tcp", proj.GetPublicId(),
		targets.WithName("test-host-source"), targets.WithTcpTargetDefaultPort(22))
	require.NoError(t, err)
	require.NotNil(t, targetResp)
	require.Empty(t, targetResp.GetItem().Address)

	// Expect error when associating a address to the target with a host source association
	targetId := targetResp.GetItem().Id
	version := targetResp.GetItem().Version
	updateResp, err := tClient.AddHostSources(tc.Context(), targetId, version, []string{hs.Item.Id})
	require.NoError(t, err)
	require.NotNil(t, updateResp)
	require.Empty(t, updateResp.GetItem().Address)
	require.Equal(t, []string{hs.Item.Id}, updateResp.GetItem().HostSourceIds)
	version = updateResp.GetItem().Version
	updateResp, err = tClient.Update(tc.Context(), targetId, version, targets.WithAddress("::1"))
	require.Error(t, err)
	require.Nil(t, updateResp)
	apiErr := api.AsServerError(err)
	require.NotNil(t, apiErr)
	require.Equal(t, http.StatusBadRequest, apiErr.Response().StatusCode())

	// Remove host source association. Successfully assign a network address to the target.
	updateResp, err = tClient.RemoveHostSources(tc.Context(), targetId, version, []string{hs.Item.Id})
	require.NoError(t, err)
	require.NotNil(t, updateResp)
	require.Empty(t, updateResp.GetItem().HostSourceIds)
	version = updateResp.GetItem().Version
	updateResp, err = tClient.Update(tc.Context(), targetId, version, targets.WithAddress("::1"))
	require.NoError(t, err)
	require.NotNil(t, updateResp)
	require.Equal(t, "::1", updateResp.GetItem().Address)
	require.Empty(t, updateResp.GetItem().HostSourceIds)
}

func TestCreateTarget_DirectlyAttachedAddress(t *testing.T) {
	tc := controller.NewTestController(t, nil)

	client := tc.Client()
	at := tc.Token()
	client.SetToken(at.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(at.UserId))
	tClient := targets.NewClient(client)

	tests := []struct {
		name            string
		address         string
		expectedAddress string
	}{
		{
			name:            "target-ipv4-address",
			address:         "127.0.0.1",
			expectedAddress: "127.0.0.1",
		},
		{
			name:            "target-ipv6-address",
			address:         "2001:BEEF:4860:0:0:0:0:8888",
			expectedAddress: "2001:beef:4860::8888",
		},
		{
			name:            "target-abbreviated-ipv6-address",
			address:         "2001:BEEF:4860::8888",
			expectedAddress: "2001:beef:4860::8888",
		},
		{
			name:            "target-dns-address",
			address:         "www.google.com",
			expectedAddress: "www.google.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			createResp, err := tClient.Create(tc.Context(), "tcp", proj.PublicId,
				targets.WithName(tt.name), targets.WithAddress(tt.address), targets.WithTcpTargetDefaultPort(22))
			require.NoError(err)
			require.NotNil(createResp)
			assert.Equal(tt.expectedAddress, createResp.GetItem().Address)

			targetId := createResp.GetItem().Id
			version := createResp.GetItem().Version
			readResp, err := tClient.Read(tc.Context(), targetId)
			require.NoError(err)
			require.NotNil(readResp)
			assert.Equal(tt.expectedAddress, readResp.GetItem().Address)

			updateResp, err := tClient.Update(tc.Context(), targetId, version, targets.DefaultAddress())
			require.NoError(err)
			require.NotNil(updateResp)
			assert.Empty(updateResp.GetItem().Address)

			readResp, err = tClient.Read(tc.Context(), targetId)
			require.NoError(err)
			require.NotNil(readResp)
			assert.Empty(readResp.GetItem().Address)
		})
	}
}

func TestUpdateTarget_DeleteAddress(t *testing.T) {
	tc := controller.NewTestController(t, nil)

	client := tc.Client()
	at := tc.Token()
	client.SetToken(at.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(at.UserId))
	tClient := targets.NewClient(client)

	assert, require := assert.New(t), require.New(t)

	// Create Target with address
	addr := "127.0.0.1"
	createResp, err := tClient.Create(tc.Context(), "tcp", proj.PublicId,
		targets.WithName("test_target_addr_delete"), targets.WithAddress(addr), targets.WithTcpTargetDefaultPort(22))
	require.NoError(err)
	require.NotNil(createResp)
	assert.Equal(addr, createResp.GetItem().Address)

	aliasedTar, err := tClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("aliased"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)
	require.NotNil(aliasedTar)

	rw := db.New(tc.DbConn())
	al := aliastar.TestAlias(t, rw, "alias.value", aliastar.WithDestinationId(aliasedTar.Item.Id))

	cases := []struct {
		name string
		id   string
	}{
		{
			name: "target id",
			id:   createResp.Item.Id,
		},
		{
			name: "aliases",
			id:   al.GetValue(),
		},
	}

	for _, c := range cases {
		// Update to delete address (set to null)
		updateResp, err := tClient.Update(tc.Context(), c.id, 1, targets.DefaultAddress())
		require.NoError(err)
		require.NotNil(updateResp)
		assert.Empty(updateResp.GetItem().Address)

		// Do it again with same version, should error
		_, err = tClient.Update(tc.Context(), c.id, 1, targets.DefaultAddress())
		require.Error(err)

		// Do it again with the correct version, ensure this is not an error.
		secondUpdateResp, err := tClient.Update(tc.Context(), c.id, updateResp.Item.Version, targets.DefaultAddress())
		require.NoError(err)
		require.NotNil(secondUpdateResp)
		assert.Empty(secondUpdateResp.GetItem().Address)

		assert.NotEqual(updateResp.Item.Version, secondUpdateResp.Item.Version)
	}
}

func comparableSlice(in []*targets.Target) []targets.Target {
	var filtered []targets.Target
	for _, i := range in {
		p := targets.Target{
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

func TestCreateWithAliases(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)

	hostId := "hst_1234567890"

	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"), targets.WithTcpTargetDefaultPort(2), targets.WithAliases([]targets.Alias{
		{
			Value:   "alias1",
			ScopeId: "global",
			Attributes: &targets.TargetAliasAttributes{
				AuthorizeSessionArguments: &targets.AuthorizeSessionArguments{
					HostId: hostId,
				},
			},
		},
		{
			Value:   "alias2",
			ScopeId: "global",
		},
	}))
	require.NoError(err)
	assert.NotNil(tar)
	assert.Len(tar.GetItem().Aliases, 2)
	assert.NotEmpty(tar.GetItem().Aliases[0].Id)
	assert.NotEmpty(tar.GetItem().Aliases[1].Id)
	assert.NotEqual(tar.GetItem().Aliases[0].Value, tar.GetItem().Aliases[1].Value)

	aliasClient := aliases.NewClient(client)
	a1, err := aliasClient.Read(tc.Context(), tar.GetItem().Aliases[0].Id)
	require.NoError(err)
	assert.Equal("alias1", a1.Item.Value)
}

func TestCrud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	checkResource := func(t *testing.T, step string, h *targets.Target, err error, wantedName string, wantVersion uint32) {
		t.Helper()
		require.NoError(err, step)
		assert.NotNil(h, "returned no resource", step)
		gotName := ""
		if h.Name != "" {
			gotName = h.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, h.Version)
	}

	tarClient := targets.NewClient(client)

	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"), targets.WithTcpTargetDefaultPort(2))
	checkResource(t, "create", tar.Item, err, "foo", 1)

	aliasedTar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("aliased"), targets.WithTcpTargetDefaultPort(2))
	checkResource(t, "create", aliasedTar.Item, err, "aliased", 1)

	rw := db.New(tc.DbConn())
	al := aliastar.TestAlias(t, rw, "alias.value", aliastar.WithDestinationId(aliasedTar.Item.Id))

	cases := []struct {
		name        string
		id          string
		initialName string
	}{
		{
			name:        "target id",
			id:          tar.Item.Id,
			initialName: "foo",
		},
		{
			name:        "aliases",
			id:          al.GetValue(),
			initialName: "aliased",
		},
	}
	for _, c := range cases {
		tar, err := tarClient.Read(tc.Context(), c.id)
		checkResource(t, "read", tar.Item, err, c.initialName, 1)

		tar, err = tarClient.Update(tc.Context(), c.id, tar.Item.Version, targets.WithName("bar"))
		checkResource(t, "update", tar.Item, err, "bar", 2)

		_, err = tarClient.Delete(tc.Context(), c.id)
		assert.NoError(err)
	}

	t.Run("deleting unknown target is not found", func(t *testing.T) {
		_, err = tarClient.Delete(tc.Context(), tar.Item.Id)
		assert.Error(err)
		apiErr := api.AsServerError(err)
		assert.NotNil(apiErr)
		assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
	})

	t.Run("deleting unknown alias is not found", func(t *testing.T) {
		_, err = tarClient.Delete(tc.Context(), al.GetValue())
		assert.Error(err)
		apiErr := api.AsServerError(err)
		assert.NotNil(apiErr)
		assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
	})
}

func TestSet_Errors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)

	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(err)
	assert.NotNil(tar)
	validTargetId := tar.GetItem().Id

	// A malformed id is processed as the id and not a different path to the api.
	_, err = tarClient.Read(tc.Context(), fmt.Sprintf("%s/../", tar.Item.Id))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
	require.Len(apiErr.Details.RequestFields, 1)
	assert.Equal(apiErr.Details.RequestFields[0].Name, "id")

	// Updating using WithAliases should fail.
	_, err = tarClient.Update(tc.Context(), tar.Item.Id, tar.Item.Version, targets.WithAliases([]targets.Alias{{Value: "alias1", ScopeId: "global"}}))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

	// Updating the wrong version should fail.
	_, err = tarClient.Update(tc.Context(), tar.Item.Id, 73, targets.WithName("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	tar, err = tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.Nil(tar)

	_, err = tarClient.Read(tc.Context(), globals.TcpTargetPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = tarClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// reading by alias with no destination id should fail
	rw := db.New(tc.DbConn())
	al := aliastar.TestAlias(t, rw, "alias.value")
	_, err = tarClient.Read(tc.Context(), al.GetValue())
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	client.SetToken("at_1234567890_madeupinvalidtoken")
	tarClient = targets.NewClient(client)
	_, err = tarClient.Read(tc.Context(), validTargetId)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusUnauthorized, apiErr.Response().StatusCode())
}

func TestCreateTarget_WhitespaceInAddress(t *testing.T) {
	require := require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)

	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"), targets.WithTcpTargetDefaultPort(2), targets.WithAddress(" 127.0.0.1 "))
	require.NoError(err)
	require.NotNil(tar)
	require.Equal("127.0.0.1", tar.GetItem().Address)
}

func TestUpdateTarget_WhitespaceInAddress(t *testing.T) {
	require := require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)

	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"), targets.WithTcpTargetDefaultPort(2), targets.WithAddress("127.0.0.1"))
	require.NoError(err)
	require.NotNil(tar)

	updateResult, err := tarClient.Update(tc.Context(), tar.Item.Id, tar.Item.Version, targets.WithAddress(" 10.0.0.1 "))
	require.NoError(err)
	require.NotNil(updateResult)
	require.Equal("10.0.0.1", updateResult.Item.Address)
}

// TestCreateTarget_SlashesInName verifies that we can prop'ly route when using
// a target name for authorizing a session and the name contains slashes
func TestCreateTarget_SlashesInName(t *testing.T) {
	require := require.New(t)
	tc := controller.NewTestController(t, nil)

	tw, _ := worker.NewAuthorizedPkiTestWorker(t, tc.ServersRepo(), "test", tc.ClusterAddrs())
	require.NotNil(tw)

	helper.ExpectWorkers(t, tc, tw)
	// Wait for an extra routing info update for good measure
	// TODO(https://hashicorp.atlassian.net/browse/ICU-16124): why is this necessary?
	require.NoError(tw.Worker().WaitForNextSuccessfulRoutingInfoUpdate())

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)

	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo/bar"), targets.WithTcpTargetDefaultPort(2), targets.WithAddress("127.0.0.1"))
	require.NoError(err)
	require.NotNil(tar)

	authzResult, err := tarClient.AuthorizeSession(tc.Context(), "", targets.WithName("foo/bar"), targets.WithScopeId(proj.PublicId))
	require.NoError(err)
	require.NotNil(authzResult)
}
