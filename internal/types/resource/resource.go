package resource

// Type defines the types of resources in the system
type Type int

const (
	Unknown           Type = 0
	Scope             Type = 1
	User              Type = 2
	Group             Type = 3
	Role              Type = 4
	Org               Type = 5
	GroupMember       Type = 6
	GroupUserMember   Type = 7
	AssignedRole      Type = 8
	AssignedUserRole  Type = 9
	AssignedGroupRole Type = 10
	RoleGrant         Type = 11
	AuthMethod        Type = 12
	Project           Type = 13
	All               Type = 14
	HostCatalog       Type = 15
	HostSet           Type = 16
	Host              Type = 17
	Target            Type = 18
	Global            Type = 19
	AuthToken         Type = 20
)

func (r Type) String() string {
	return [...]string{
		"unknown",
		"scope",
		"user",
		"group",
		"role",
		"org",
		"group-member",
		"group-user-member",
		"assigned-role",
		"assigned-user-role",
		"assigned-group-role",
		"role-grant",
		"auth-method",
		"project",
		"*",
		"host-catalog",
		"host-set",
		"host",
		"target",
		"global",
		"auth-token",
	}[r]
}

var Map = map[string]Type{
	Scope.String():             Scope,
	User.String():              User,
	Group.String():             Group,
	Role.String():              Role,
	Org.String():               Org,
	GroupMember.String():       GroupMember,
	GroupUserMember.String():   GroupUserMember,
	AssignedRole.String():      AssignedRole,
	AssignedUserRole.String():  AssignedUserRole,
	AssignedGroupRole.String(): AssignedGroupRole,
	RoleGrant.String():         RoleGrant,
	AuthMethod.String():        AuthMethod,
	Project.String():           Project,
	All.String():               All,
	HostCatalog.String():       HostCatalog,
	HostSet.String():           HostSet,
	Host.String():              Host,
	Target.String():            Target,
	Global.String():            Global,
	Group.String():             Group,
	AuthToken.String():         AuthToken,
}
