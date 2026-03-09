// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
)

// CreateOrgApi creates a new organization in boundary using the Go api.
// Returns the id of the new org.
func CreateOrgApi(t testing.TB, ctx context.Context, client *api.Client) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	scopeClient := scopes.NewClient(client)
	createOrgResult, err := scopeClient.Create(ctx, "global", scopes.WithName(fmt.Sprintf("e2e Org %s", name)))
	if err != nil {
		return "", err
	}

	orgId := createOrgResult.Item.Id
	t.Logf("Created Org Id: %s", orgId)
	return orgId, nil
}

// CreateProjectApi creates a new project in boundary using the Go api. The project will be created
// under the provided org id.
// Returns the id of the new project.
func CreateProjectApi(t testing.TB, ctx context.Context, client *api.Client, orgId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	scopeClient := scopes.NewClient(client)
	createProjResult, err := scopeClient.Create(ctx, orgId, scopes.WithName(fmt.Sprintf("e2e Project %s", name)))
	if err != nil {
		return "", err
	}

	projectId := createProjResult.Item.Id
	t.Logf("Created Project Id: %s", projectId)
	return projectId, nil
}

// CreateOrgCli creates a new organization in boundary using the cli.
// Returns the id of the new org.
func CreateOrgCli(t testing.TB, ctx context.Context, opt ...e2e.Option) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	var options []e2e.Option
	options = append(options,
		e2e.WithArgs(
			"scopes", "create",
			"-name", fmt.Sprintf("e2e Org %s", name),
			"-description", "e2e",
			"-scope-id", "global",
			"-format", "json",
		),
	)
	options = append(options, opt...)

	output := e2e.RunCommand(ctx, "boundary",
		options...,
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createOrgResult scopes.ScopeCreateResult
	err = json.Unmarshal(output.Stdout, &createOrgResult)
	if err != nil {
		return "", err
	}

	orgId := createOrgResult.Item.Id
	t.Logf("Created Org Id: %s", orgId)
	return orgId, nil
}

// CreateProjectCli creates a new project in boundary using the cli. The project will be created
// under the provided org id.
// Returns the id of the new project.
func CreateProjectCli(t testing.TB, ctx context.Context, orgId string, opt ...e2e.Option) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	var options []e2e.Option
	options = append(options,
		e2e.WithArgs("scopes", "create",
			"-scope-id", orgId,
			"-name", fmt.Sprintf("e2e Org %s", name),
			"-description", "e2e",
			"-format", "json"),
	)

	options = append(options, opt...)

	output := e2e.RunCommand(ctx, "boundary",
		options...,
	)

	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createProjResult scopes.ScopeCreateResult
	err = json.Unmarshal(output.Stdout, &createProjResult)
	if err != nil {
		return "", err
	}

	projectId := createProjResult.Item.Id
	t.Logf("Created Project Id: %s", projectId)
	return projectId, nil
}
