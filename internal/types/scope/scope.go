// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package scope

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// Type defines the possible types for Scopes
type Type uint

const (
	Unknown Type = iota
	Global
	Org
	Project
)

func (s Type) String() string {
	return [...]string{
		"unknown",
		"global",
		"org",
		"project",
	}[s]
}

func (s Type) Prefix() string {
	return [...]string{
		"unknown",
		globals.GlobalPrefix,
		globals.OrgPrefix,
		globals.ProjectPrefix,
	}[s]
}

var Map = map[string]Type{
	Global.String():  Global,
	Org.String():     Org,
	Project.String(): Project,
}

// AllowedIn returns the set of Scopes a known Resource type is allowed in.
func AllowedIn(ctx context.Context, r resource.Type) ([]Type, error) {
	const op = "scope.AllowedIn"
	switch r {
	case resource.Alias, resource.Billing, resource.Worker:
		return []Type{Global}, nil
	case resource.Account, resource.AuthMethod, resource.AuthToken, resource.ManagedGroup, resource.Policy, resource.SessionRecording, resource.StorageBucket, resource.User:
		return []Type{Global, Org}, nil
	case resource.Group, resource.Role, resource.Scope:
		return []Type{Global, Org, Project}, nil
	case resource.CredentialLibrary, resource.Credential, resource.CredentialStore, resource.HostCatalog, resource.HostSet, resource.Host, resource.Session, resource.Target:
		return []Type{Project}, nil
	case resource.Unknown:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unknown resource type")
	case resource.All:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type '*' is not supported")
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid resource type: %d", r))
	}
}
