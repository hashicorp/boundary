package resource

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
)

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
