package resource

// Type defines the types of resources in the system
type Type int

const (
	Unknown     Type = 0
	All         Type = 1
	Scope       Type = 2
	User        Type = 3
	Group       Type = 4
	Role        Type = 5
	RoleGrant   Type = 6
	AuthMethod  Type = 7
	Account     Type = 8
	AuthToken   Type = 9
	HostCatalog Type = 10
	HostSet     Type = 11
	Host        Type = 12
	Target      Type = 13
)

func (r Type) String() string {
	return [...]string{
		"unknown",
		"*",
		"scope",
		"user",
		"group",
		"role",
		"role-grant",
		"auth-method",
		"account",
		"auth-token",
		"host-catalog",
		"host-set",
		"host",
		"target",
	}[r]
}

var Map = map[string]Type{
	Unknown.String():     Unknown,
	All.String():         All,
	Scope.String():       Scope,
	User.String():        User,
	Group.String():       Group,
	Role.String():        Role,
	RoleGrant.String():   RoleGrant,
	AuthMethod.String():  AuthMethod,
	Account.String():     Account,
	AuthToken.String():   AuthToken,
	HostCatalog.String(): HostCatalog,
	HostSet.String():     HostSet,
	Host.String():        Host,
	Target.String():      Target,
}
