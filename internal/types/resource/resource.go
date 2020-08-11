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
	HostCatalog Type = 9
	HostSet     Type = 10
	Host        Type = 11
	Target      Type = 12
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
	HostCatalog.String(): HostCatalog,
	HostSet.String():     HostSet,
	Host.String():        Host,
	Target.String():      Target,
	Group.String():       Group,
}
