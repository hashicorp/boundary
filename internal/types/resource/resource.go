package resource

import "encoding/json"

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
	ManagedGroup
	CredentialStore
	CredentialLibrary
	// NOTE: When adding a new type, be sure to update:
	//
	// * The Grant.validateType function and test
	// * The perms.topLevelType function
	// * The scopes service collection actions for appropriate scopes
	// * The Test_AnonRestrictions test
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
		"managed-group",
		"credential-store",
		"credential-library",
	}[r]
}

func (r Type) PluralString() string {
	switch r {
	case CredentialLibrary:
		return "credential-libraries"
	default:
		return r.String() + "s"
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
	ManagedGroup.String():      ManagedGroup,
	CredentialStore.String():   CredentialStore,
	CredentialLibrary.String(): CredentialLibrary,
}
