package target_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/e2e"
	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectTargetCli(t *testing.T) {
	// !! add boundary_local_dir to path?
	var config e2e.BaseTest
	require.NoError(t, envconfig.Process("", &config))
	s, _ := json.MarshalIndent(config, "", "\t")
	log.Printf("%s", s)

	output := e2e.RunCommand([]string{
		"boundary", "authenticate", "password",
		"-addr", config.BoundaryAddress,
		"-auth-method-id", config.BoundaryAuthMethodId,
		"-login-name", config.BoundaryAdminLoginName,
		"-password", "env://BOUNDARY_AUTHENTICATE_PASSWORD_PASSWORD",
	})
	require.NoError(t, output.Err, string(output.Stderr))

	// Create an org
	orgName := "mycow_org_" + time.Now().Format(time.RFC3339)
	output = e2e.RunCommand([]string{
		"boundary", "scopes", "create",
		"-name", orgName,
		"-format", "json",
	})
	require.NoError(t, output.Err, string(output.Stderr))
	var newOrgResult scopes.ScopeCreateResult
	err := json.Unmarshal(output.Stdout, &newOrgResult)
	require.NoError(t, err)
	newOrg := newOrgResult.Item
	t.Cleanup(func() {
		e2e.RunCommand([]string{"boundary", "scopes", "delete", "-id", newOrg.Id})
	})
	t.Logf("Created Org Id: %s", newOrg.Id)

	// Create a project
	output = e2e.RunCommand([]string{
		"boundary", "scopes", "create",
		"-scope-id", newOrg.Id,
		"-name", "e2e Automated Test Project",
		"-format", "json",
	})
	require.NoError(t, output.Err, string(output.Stderr))
	var newProjectResult scopes.ScopeCreateResult
	err = json.Unmarshal(output.Stdout, &newProjectResult)
	require.NoError(t, err)
	newProject := newProjectResult.Item
	t.Cleanup(func() {
		e2e.RunCommand([]string{"boundary", "scopes", "delete", "-id", newProject.Id})
	})
	t.Logf("Created Project Id: %s", newProject.Id)

	// Create a host catalog
	output = e2e.RunCommand([]string{
		"boundary", "host-catalogs", "create", "static",
		"-scope-id", newProject.Id,
		"-name", "e2e Automated Test Host Catalog",
		"-format", "json",
	})
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostCatalogResult hostcatalogs.HostCatalogCreateResult
	err = json.Unmarshal(output.Stdout, &newHostCatalogResult)
	require.NoError(t, err)
	newHostCatalog := newHostCatalogResult.Item
	t.Cleanup(func() {
		e2e.RunCommand([]string{"boundary", "host-catalogs", "delete", "-id", newHostCatalog.Id})
	})
	t.Logf("Created Host Catalog: %s", newHostCatalog.Id)

	// Create a host set and add to catalog
	output = e2e.RunCommand([]string{
		"boundary", "host-sets", "create", "static",
		"-host-catalog-id", newHostCatalog.Id,
		"-name", "e2e Automated Test Host Set",
		"-format", "json",
	})
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostSetResult hostsets.HostSetCreateResult
	err = json.Unmarshal(output.Stdout, &newHostSetResult)
	require.NoError(t, err)
	newHostSet := newHostSetResult.Item
	t.Cleanup(func() {
		e2e.RunCommand([]string{"boundary", "host-sets", "delete", "-id", newHostSet.Id})
	})
	t.Logf("Created Host Set: %s", newHostSet.Id)

	// Create a host
	output = e2e.RunCommand([]string{
		"boundary", "hosts", "create", "static",
		"-host-catalog-id", newHostCatalog.Id,
		"-name", config.BoundaryTargetIp,
		"-address", config.BoundaryTargetIp,
		"-format", "json",
	})
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostResult hosts.HostCreateResult
	err = json.Unmarshal(output.Stdout, &newHostResult)
	require.NoError(t, err)
	newHost := newHostResult.Item
	t.Cleanup(func() {
		e2e.RunCommand([]string{"boundary", "hosts", "delete", "-id", newHost.Id})
	})
	t.Logf("Created Host: %s", newHost.Id)

	// Add host to host set
	output = e2e.RunCommand([]string{
		"boundary", "host-sets", "add-hosts",
		"-id", newHostSet.Id,
		"-host", newHost.Id,
	})
	require.NoError(t, output.Err, string(output.Stderr))

	// Create a target
	output = e2e.RunCommand([]string{
		"boundary", "targets", "create", "tcp",
		"-scope-id", newProject.Id,
		"-default-port", "22",
		"-name", "e2e Automated Test Target",
		"-format", "json",
	})
	require.NoError(t, output.Err, string(output.Stderr))
	var newTargetResult targets.TargetCreateResult
	err = json.Unmarshal(output.Stdout, &newTargetResult)
	require.NoError(t, err)
	newTarget := newTargetResult.Item
	t.Cleanup(func() {
		e2e.RunCommand([]string{"boundary", "targets", "delete", "-id", newTarget.Id})
	})
	t.Logf("Created Target: %s", newTarget.Id)

	// Add host set to target
	output = e2e.RunCommand([]string{
		"boundary", "targets", "add-host-sets",
		"-id", newTarget.Id,
		"-host-set", newHostSet.Id,
	})
	require.NoError(t, output.Err, string(output.Stderr))

	// Connect to target and print host's IP address
	output = e2e.RunCommand([]string{
		"boundary", "connect",
		"-target-id", newTarget.Id,
		"-exec", "/usr/bin/ssh", "--",
		"-l", "ubuntu",
		"-i", config.BoundaryTargetSshKeyPath,
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		"-p", "{{boundary.port}}", // this is provided by boundary
		"{{boundary.ip}}",
		"hostname", "-i",
	})
	require.NoError(t, output.Err, string(output.Stderr))

	parts := strings.Fields(string(output.Stdout))
	hostIp := parts[len(parts)-1]
	assert.Equal(t, config.BoundaryTargetIp, hostIp)
	t.Log("Successfully connected to target")
}

func TestCreateTargetApi(t *testing.T) {
	var config e2e.BaseTest
	require.NoError(t, envconfig.Process("", &config))

	client, err := api.NewClient(&api.Config{
		Addr: config.BoundaryAddress,
	})
	require.NoError(t, err)

	ctx := context.Background()
	authmethodsClient := authmethods.NewClient(client)
	authenticationResult, err := authmethodsClient.Authenticate(
		ctx,
		config.BoundaryAuthMethodId,
		"login",
		map[string]interface{}{
			"login_name": config.BoundaryAdminLoginName,
			"password":   config.BoundaryAdminLoginPassword,
		},
	)
	require.NoError(t, err)
	assert.NotNil(t, authenticationResult)
	client.SetToken(fmt.Sprint(authenticationResult.Attributes["token"]))
	// !! new package Boundary.NewAdminClient -> return client (that has the token) or error

	// Create an org
	orgName := "mycow_org_" + time.Now().Format(time.RFC3339)
	scopeClient := scopes.NewClient(client)
	newOrgResult, err := scopeClient.Create(ctx, "global", scopes.WithName(orgName))
	require.NoError(t, err)
	newOrg := newOrgResult.Item
	t.Cleanup(func() {
		scopeClient.Delete(ctx, newOrg.Id)
	})
	t.Logf("Created Org Id: %s", newOrg.Id)

	// Create a project
	newProjectResult, err := scopeClient.Create(ctx, newOrg.Id, scopes.WithName("e2e Automated Test Project"))
	require.NoError(t, err)
	newProject := newProjectResult.Item
	t.Cleanup(func() {
		scopeClient.Delete(ctx, newProject.Id)
	})
	t.Logf("Created Project Id: %s", newProject.Id)

	// Create a host catalog
	hcClient := hostcatalogs.NewClient(client)
	newHostCatalogResult, err := hcClient.Create(ctx, "static", newProject.Id,
		hostcatalogs.WithName("e2e Automated Test Host Catalog"),
	)
	require.NoError(t, err)
	newHostCatalog := newHostCatalogResult.Item
	t.Cleanup(func() {
		hcClient.Delete(ctx, newHostCatalog.Id)
	})
	t.Logf("Created Host Catalog: %s", newHostCatalog.Id)

	// Create a host set and add to catalog
	hsClient := hostsets.NewClient(client)
	newHostSetResult, err := hsClient.Create(ctx, newHostCatalog.Id)
	require.NoError(t, err)
	newHostSet := newHostSetResult.Item
	t.Cleanup(func() {
		hsClient.Delete(ctx, newHostSet.Id)
	})
	t.Logf("Created Host Set: %s", newHostSet.Id)

	// Create a host
	hClient := hosts.NewClient(client)
	newHostResult, err := hClient.Create(ctx, newHostCatalog.Id,
		hosts.WithName(config.BoundaryTargetIp),
		hosts.WithStaticHostAddress(config.BoundaryTargetIp),
	)
	require.NoError(t, err)
	newHost := newHostResult.Item
	t.Cleanup(func() {
		hClient.Delete(ctx, newHost.Id)
	})
	t.Logf("Created Host: %s", newHost.Id)

	// Add host to host set
	_, err = hsClient.AddHosts(ctx, newHostSet.Id, 0, []string{newHost.Id}, hostsets.WithAutomaticVersioning(true))
	require.NoError(t, err)

	// Create a target
	tClient := targets.NewClient(client)
	newTargetResult, err := tClient.Create(ctx, "tcp", newProject.Id,
		targets.WithName("e2e Automated Test Target"),
		targets.WithTcpTargetDefaultPort(22),
	)
	require.NoError(t, err)
	newTarget := newTargetResult.Item
	t.Cleanup(func() {
		tClient.Delete(ctx, newTarget.Id)
	})
	t.Logf("Created Target: %s", newTarget.Id)

	// Add host set to target
	_, err = tClient.AddHostSets(ctx, newTarget.Id, 0,
		[]string{newHostSet.Id},
		targets.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)
}
