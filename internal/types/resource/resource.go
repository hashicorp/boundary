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
	AuthMethod  Type = 6
	Account     Type = 7
	AuthToken   Type = 8
	HostCatalog Type = 9
	HostSet     Type = 10
	Host        Type = 11
	Target      Type = 12
	Controller  Type = 13
	Worker      Type = 14
	Session     Type = 15
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
	}[r]
}

var Map = map[string]Type{
	Unknown.String():     Unknown,
	All.String():         All,
	Scope.String():       Scope,
	User.String():        User,
	Group.String():       Group,
	Role.String():        Role,
	AuthMethod.String():  AuthMethod,
	Account.String():     Account,
	AuthToken.String():   AuthToken,
	HostCatalog.String(): HostCatalog,
	HostSet.String():     HostSet,
	Host.String():        Host,
	Target.String():      Target,
	Controller.String():  Controller,
	Worker.String():      Worker,
	Session.String():     Session,
}
