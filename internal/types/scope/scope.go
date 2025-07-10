// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package scope

import "github.com/hashicorp/boundary/globals"

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
