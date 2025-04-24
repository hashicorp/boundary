// Copyright (c) HashiCorp, Inc.
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
func CreateOrgCli(t testing.TB, ctx context.Context) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "create",
			"-name", fmt.Sprintf("e2e Org %s", name),
			"-description", "e2e",
			"-scope-id", "global",
			"-format", "json",
		),
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
func CreateProjectCli(t testing.TB, ctx context.Context, orgId string, opt ...ScopeOption) (string, error) {
	opts := getScopeOpts(opt...)
	var args []string

	args = append(args,
		"scopes", "create",
		"-scope-id", orgId,
		"-description", "e2e",
		"-format", "json",
	)

	if opts.WithName != "" {
		args = append(args, "-name", opts.WithName)
	} else {
		name, err := base62.Random(16)
		if err != nil {
			return "", err
		}
		args = append(args, "-name", fmt.Sprintf("e2e Project %s", name))
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(args...),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createProjResult scopes.ScopeCreateResult
	err := json.Unmarshal(output.Stdout, &createProjResult)
	if err != nil {
		return "", err
	}

	projectId := createProjResult.Item.Id
	t.Logf("Created Project Id: %s", projectId)
	return projectId, nil
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
