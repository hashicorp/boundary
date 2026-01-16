// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package resource

import (
	"encoding/json"
	"strings"
)

// Type defines the types of resources in the system
type Type uint

const (
	Unknown Type = iota
	All
	Scope
	User
	Group
	Role
	AuthMethod
	Account
	AuthToken
	HostCatalog
	HostSet
	Host
	Target
	Controller
	Worker
	Session
	SessionRecording
	ManagedGroup
	CredentialStore
	CredentialLibrary
	Credential
	StorageBucket
	Policy
	Billing
	Alias
	// NOTE: When adding a new type, be sure to update:
	//
	// * The Grant.validateType function and test
	// * The perms.topLevelType function
	// * The scopes service collection actions for appropriate scopes
	// * The Test_AnonRestrictions test: update the following line to include the last resource:
	//      for i := resource.Type(1); i <= resource.<Resource>; i++ {
	// * The prefixes and mappings in globals/prefixes.go
	// * The AllowedIn function & its test in the scope package
)

func (r Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r Type) String() string {
	return [...]string{
		"unknown",
		"*",
		"scope",
		"user",
		"group",
		"role",
		"auth-method",
		"account",
		"auth-token",
		"host-catalog",
		"host-set",
		"host",
		"target",
		"controller",
		"worker",
		"session",
		"session-recording",
		"managed-group",
		"credential-store",
		"credential-library",
		"credential",
		"storage-bucket",
		"policy",
		"billing",
		"alias",
	}[r]
}

func (r Type) PluralString() string {
	switch r {
	case CredentialLibrary:
		return "credential-libraries"
	case Policy:
		return "policies"
	case Billing: // never pluralized
		return "billing"
	case Alias:
		return "aliases"
	default:
		return r.String() + "s"
	}
}

func FromPlural(s string) (Type, bool) {
	switch s {
	case "credential-libraries":
		return CredentialLibrary, true
	case "policies":
		return Policy, true
	case "billing":
		return Billing, true
	case "aliases":
		return Alias, true
	default:
		t, ok := Map[strings.TrimSuffix(s, "s")]
		return t, ok
	}
}

var Map = map[string]Type{
	Unknown.String():           Unknown,
	All.String():               All,
	Scope.String():             Scope,
	User.String():              User,
	Group.String():             Group,
	Role.String():              Role,
	AuthMethod.String():        AuthMethod,
	Account.String():           Account,
	AuthToken.String():         AuthToken,
	HostCatalog.String():       HostCatalog,
	HostSet.String():           HostSet,
	Host.String():              Host,
	Target.String():            Target,
	Controller.String():        Controller,
	Worker.String():            Worker,
	Session.String():           Session,
	SessionRecording.String():  SessionRecording,
	ManagedGroup.String():      ManagedGroup,
	CredentialStore.String():   CredentialStore,
	CredentialLibrary.String(): CredentialLibrary,
	Credential.String():        Credential,
	StorageBucket.String():     StorageBucket,
	Policy.String():            Policy,
	Billing.String():           Billing,
	Alias.String():             Alias,
}

// Parent returns the parent type for a given type; if there is no parent, it
// returns the incoming type
func (r Type) Parent() Type {
	switch r {
	case Account, ManagedGroup:
		return AuthMethod
	case HostSet, Host:
		return HostCatalog
	case CredentialLibrary, Credential:
		return CredentialStore
	}
	return r
}

// HasChildTypes indicates whether this is a type that has child resource types;
// it's essentially the inverse of Parent
func (r Type) HasChildTypes() bool {
	switch r {
	case AuthMethod, HostCatalog, CredentialStore:
		return true
	}
	return false
}

// TopLevelType indicates whether this is a type that supports collection
// actions, e.g. Create/List
func (r Type) TopLevelType() bool {
	switch r {
	case AuthMethod,
		AuthToken,
		CredentialStore,
		Group,
		HostCatalog,
		Role,
		Scope,
		Session,
		SessionRecording,
		Target,
		User,
		StorageBucket,
		Policy,
		Alias,
		Worker:
		return true
	}
	return false
}
