// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package oidc

// AuthMethodState defines the possible states for an oidc auth method
type AuthMethodState string

const (
	UnknownState       AuthMethodState = "unknown"
	InactiveState      AuthMethodState = "inactive"
	ActivePrivateState AuthMethodState = "active-private"
	ActivePublicState  AuthMethodState = "active-public"
)

func validState(s string) bool {
	st := AuthMethodState(s)
	switch st {
	case InactiveState, ActivePrivateState, ActivePublicState:
		return true
	default:
		return false
	}
}
