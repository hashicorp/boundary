// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
)

// CreateRoleApi creates a new role using the Go api.
// Returns the id of the new role
func CreateRoleApi(t testing.TB, ctx context.Context, client *api.Client, scopeId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	rClient := roles.NewClient(client)
	createRoleResult, err := rClient.Create(ctx, scopeId, roles.WithName(fmt.Sprintf("e2e Role %s", name)))
	if err != nil {
		return "", err
	}

	roleId := createRoleResult.Item.Id
	t.Logf("Created Role: %s", roleId)
	return roleId, nil
}

// CreateRoleCli creates a new role using the Boundary CLI.
// Returns the id of the new role or error
func CreateRoleCli(t testing.TB, ctx context.Context, scopeId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "create",
			"-scope-id", scopeId,
			"-name", fmt.Sprintf("e2e Role %s", name),
			"-description", "e2e",
			"-format", "json",
		),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createRoleResult roles.RoleCreateResult
	if err := json.Unmarshal(output.Stdout, &createRoleResult); err != nil {
		return "", fmt.Errorf("error unmarshalling role creation result: %w", err)
	}

	roleId := createRoleResult.Item.Id
	t.Logf("Created Role: %s in scope %s", roleId, scopeId)
	return roleId, nil
}

// ListRolesCli lists roles from the specified scope using the Boundary CLI.
// Returns a slice of roles or error
func ListRolesCli(t testing.TB, ctx context.Context, scopeId string) ([]*roles.Role, error) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "list",
			"-scope-id", scopeId,
			"-format", "json",
		),
	)
	if output.Err != nil {
		return nil, fmt.Errorf("error listing roles in %s scope: %w: %s", scopeId, output.Err, output.Stderr)
	}

	var roleListResult roles.RoleListResult
	if err := json.Unmarshal(output.Stdout, &roleListResult); err != nil {
		return nil, fmt.Errorf("error unmarshalling role list result: %w", err)
	}

	t.Logf("Listed Roles in scope %s", scopeId)
	return roleListResult.Items, nil
}

// AddGrantToRoleCli adds a grant/permission to a role using the cli
func AddGrantToRoleCli(t testing.TB, ctx context.Context, roleId string, grant string) error {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "add-grants",
			"-id", roleId,
			"-grant", grant,
		),
	)
	if output.Err != nil {
		return fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	return nil
}

// AddPrincipalToRoleCli adds a user/group to a role using the cli
func AddPrincipalToRoleCli(t testing.TB, ctx context.Context, roleId string, principal string) error {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "add-principals",
			"-id", roleId,
			"-principal", principal,
		),
	)
	if output.Err != nil {
		return fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	t.Logf("Principal %s added to role: %s", principal, roleId)
	return nil
}

// SetGrantScopesToRoleCli uses Boundary CLI to override grant scopes for the role with the provided ones.
// Option WithGrantScopeId can be used multiple times to provide grant scope IDs.
func SetGrantScopesToRoleCli(t testing.TB, ctx context.Context, roleId string, opt ...RoleOption) error {
	opts := getRoleOpts(opt...)
	var args []string

	if len(opts.scopeIds) == 0 {
		return fmt.Errorf("at least one grant scope id must be provided")
	}
	for _, id := range opts.scopeIds {
		args = append(args, "-grant-scope-id", id)
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "set-grant-scopes",
			"-id", roleId,
		),
		e2e.WithArgs(args...),
	)
	if output.Err != nil {
		return fmt.Errorf("error setting grant scopes to role: %w: %s", output.Err, string(output.Stderr))
	}

	t.Logf("Grant scopes are set to role %s: %v", roleId, opts.scopeIds)
	return nil
}

// getRoleOpts iterates the inbound RoleOptions and returns a struct.
func getRoleOpts(opt ...RoleOption) roleOptions {
	opts := roleOptions{
		scopeIds: make([]string, 0),
	}
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// RoleOption represents how Options are passed as arguments.
type RoleOption func(*roleOptions)

// roleOptions is a struct representing available options for roles.
type roleOptions struct {
	scopeIds []string
}

// WithGrantScopeId provides an option to set the grant scope to a role.
func WithGrantScopeId(scopeId string) RoleOption {
	return func(o *roleOptions) {
		o.scopeIds = append(o.scopeIds, scopeId)
	}
}
