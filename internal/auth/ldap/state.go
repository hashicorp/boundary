// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

// AuthMethodState defines the possible states for an ldap auth method
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

func (s AuthMethodState) String() string {
	return string(s)
}
