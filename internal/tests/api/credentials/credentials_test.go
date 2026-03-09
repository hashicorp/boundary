// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentials_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/go-hclog"
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

	obj := map[string]any{
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

	cred, err = credClient.Update(tc.Context(), cred.Item.Id, cred.Item.Version, credentials.WithJsonCredentialObject(map[string]any{
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

	_, err = c.Read(tc.Context(), globals.UsernamePasswordCredentialPrefix+"_doesntexis")
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

// TestUpdateAfterKeyRotation sets up a scenario where a JSON credential
// is re-encrypted with the newest key version during an update, and checks
// that the key version ID is tracked correctly. If the key version ID
// is not updated during the credential update, the data becomes
// irrecoverable since the encryption key is destroyed.
func TestUpdateAfterKeyRotation(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	// This prevents us from running tests in parallel.
	server.TestUseCommunityFilterWorkersFn(t)

	tc := controller.NewTestController(
		t,
		&controller.TestControllerOpts{
			SchedulerRunJobInterval: 100 * time.Millisecond,
			DisableRateLimiting:     true,
		},
	)
	ctx := tc.Context()
	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	scopesClient := scopes.NewClient(client)
	credsClient := credentials.NewClient(client)
	tgClient := targets.NewClient(client)
	hostClient := hosts.NewClient(client)
	hsClient := hostsets.NewClient(client)
	hcClient := hostcatalogs.NewClient(client)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	hc, err := hcClient.Create(ctx, "static", proj.PublicId, hostcatalogs.WithName("my-host-catalog"))
	require.NoError(err)
	host, err := hostClient.Create(ctx, hc.Item.Id, hosts.WithName("my-host"), hosts.WithStaticHostAddress("example.com"))
	require.NoError(err)
	hs, err := hsClient.Create(ctx, hc.Item.Id, hostsets.WithName("my-host-set"))
	require.NoError(err)
	_, err = hsClient.AddHosts(ctx, hs.Item.Id, 1, []string{host.Item.Id})
	require.NoError(err)
	cs, err := credentialstores.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)
	obj := map[string]any{
		"username": "admin",
		"password": "pass",
	}
	cred, err := credsClient.Create(ctx, credential.JsonSubtype.String(), cs.Item.Id, credentials.WithName("foo"), credentials.WithJsonCredentialObject(obj))
	require.NoError(err)
	targ, err := tgClient.Create(ctx, "tcp", proj.PublicId, targets.WithName("my-target"), targets.WithTcpTargetDefaultPort(22))
	require.NoError(err)
	_, err = tgClient.AddHostSources(ctx, targ.Item.Id, 1, []string{hs.Item.Id})
	require.NoError(err)
	_, err = tgClient.AddCredentialSources(ctx, targ.Item.Id, 2, targets.WithBrokeredCredentialSourceIds([]string{cred.Item.Id}))
	require.NoError(err)
	w := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		InitialUpstreams: tc.ClusterAddrs(),
		Logger:           logger.Named("worker"),
		WorkerAuthKms:    tc.Config().WorkerAuthKms,
		Name:             "worker",
	})
	helper.ExpectWorkers(t, tc, w)

	// Authorize session, requires decrypting json credential
	_, err = tgClient.AuthorizeSession(ctx, targ.Item.Id)
	require.NoError(err)

	// Create new key versions
	_, err = scopesClient.RotateKeys(ctx, proj.PublicId, false)
	require.NoError(err)

	// Update JSON credential, will re-encrypt with new key versions
	obj["password"] = "password"
	_, err = credsClient.Update(ctx, cred.Item.Id, 1, credentials.WithJsonCredentialObject(obj))
	require.NoError(err)

	// Create new key versions again
	_, err = scopesClient.RotateKeys(ctx, proj.PublicId, false)
	require.NoError(err)

	keys, err := scopesClient.ListKeys(ctx, proj.PublicId)
	require.NoError(err)

	var destroyKeyVersion *scopes.KeyVersion

	for _, key := range keys.Items {
		if key.Purpose == kms.KeyPurposeDatabase.String() {
			// Versions are sorted in descending order, this gets the 2nd version.
			// It is the keyversion that was used to re-encrypt our JSON credential.
			destroyKeyVersion = key.Versions[1]
			break
		}
	}

	// Destroy the older key version
	result, err := scopesClient.DestroyKeyVersion(ctx, proj.PublicId, destroyKeyVersion.Id)
	require.NoError(err)
	// Should start asynchronous rewrapping of the encrypted JSON credential
	assert.Equal("pending", result.State)

	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for {
		jobs, err := scopesClient.ListKeyVersionDestructionJobs(ctx, proj.PublicId)
		require.NoError(err)
		if len(jobs.Items) >= 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("Timed out waiting for key version destruction job, got jobs: %#v", jobs.Items)
			break
		case <-time.After(time.Millisecond * 100):
		}
	}

	// Authorize session, requires decrypting json credential again
	_, err = tgClient.AuthorizeSession(ctx, targ.Item.Id)
	require.NoError(err)
}
