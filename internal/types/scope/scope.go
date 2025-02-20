// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package scope

import (
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// Type defines the possible types for Scopes
type Type uint

const (
	Unknown Type = 0
	Global  Type = 1
	Org     Type = 2
	Project Type = 3
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

// AllowedIn returns the set of Scopes a Resource is allowed in.
func AllowedIn(r resource.Type) []Type {
	switch r {
	case resource.Alias, resource.Billing, resource.Worker:
		return []Type{Global}
	case resource.Account, resource.AuthMethod, resource.AuthToken, resource.ManagedGroup, resource.Policy, resource.Scope, resource.SessionRecording, resource.StorageBucket, resource.User:
		return []Type{Global, Org}
	case resource.All, resource.Group, resource.Role:
		return []Type{Global, Org, Project}
	case resource.CredentialLibrary, resource.Credential, resource.CredentialStore, resource.HostCatalog, resource.HostSet, resource.Host, resource.Session, resource.Target:
		return []Type{Project}
	default:
		return []Type{Unknown}
	}
}
