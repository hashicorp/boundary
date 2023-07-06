// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package boundary

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewOrgApi creates a new organization in boundary using the Go api.
// Returns the id of the new org.
func CreateNewOrgApi(t testing.TB, ctx context.Context, client *api.Client) string {
	scopeClient := scopes.NewClient(client)
	newOrgResult, err := scopeClient.Create(ctx, "global", scopes.WithName("e2e Org"))
	require.NoError(t, err)

	newOrgId := newOrgResult.Item.Id
	t.Logf("Created Org Id: %s", newOrgId)
	return newOrgId
}

// CreateNewProjectApi creates a new project in boundary using the Go api. The project will be created
// under the provided org id.
// Returns the id of the new project.
func CreateNewProjectApi(t testing.TB, ctx context.Context, client *api.Client, orgId string) string {
	scopeClient := scopes.NewClient(client)
	newProjResult, err := scopeClient.Create(ctx, orgId, scopes.WithName("e2e Project"))
	require.NoError(t, err)

	newProjectId := newProjResult.Item.Id
	t.Logf("Created Project Id: %s", newProjectId)
	return newProjectId
}

// CreateNewOrgCli creates a new organization in boundary using the cli.
// Returns the id of the new org.
func CreateNewOrgCli(t testing.TB, ctx context.Context) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "create",
			"-name", "e2e Org",
			"-scope-id", "global",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newOrgResult scopes.ScopeCreateResult
	err := json.Unmarshal(output.Stdout, &newOrgResult)
	require.NoError(t, err)

	newOrgId := newOrgResult.Item.Id
	t.Logf("Created Org Id: %s", newOrgId)
	return newOrgId
}

// CreateNewProjectCli creates a new project in boundary using the cli. The project will be created
// under the provided org id.
// Returns the id of the new project.
func CreateNewProjectCli(t testing.TB, ctx context.Context, orgId string, opt ...ScopeOption) string {
	opts := getScopeOpts(opt...)
	var args []string

	args = append(args,
		"scopes", "create",
		"-scope-id", orgId,
		"-format", "json",
	)

	if opts.WithName != "" {
		args = append(args, "-name", opts.WithName)
	} else {
		args = append(args, "-name", "e2e Project")
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(args...),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newProjResult scopes.ScopeCreateResult
	err := json.Unmarshal(output.Stdout, &newProjResult)
	require.NoError(t, err)

	newProjectId := newProjResult.Item.Id
	t.Logf("Created Project Id: %s", newProjectId)
	return newProjectId
}

// getScopeOpts iterates the inbound ScopeOptions and returns a struct
func getScopeOpts(opt ...ScopeOption) scopeOptions {
	opts := scopeOptions{
		WithName: "",
	}
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// ScopeOption represents how Options are passed as arguments
type ScopeOption func(*scopeOptions)

// scopeOptions is a struct representing available options for scopes
type scopeOptions struct {
	WithName string
}

// WithName provides an option to search by a friendly name
func WithName(name string) ScopeOption {
	return func(o *scopeOptions) {
		o.WithName = name
	}
}
