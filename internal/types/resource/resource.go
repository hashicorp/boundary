package resource

// Type defines the types of resources in the system
type Type int

const (
	Unknown                 Type = 0
	Scope                   Type = 1
	User                    Type = 2
	StaticGroup             Type = 3
	Role                    Type = 4
	Org                     Type = 5
	StaticGroupMember       Type = 6
	StaticGroupUserMember   Type = 7
	AssignedRole            Type = 8
	AssignedUserRole        Type = 9
	AssignedStaticGroupRole Type = 10
	RoleGrant               Type = 11
	AuthMethod              Type = 12
	Project                 Type = 13
	All                     Type = 14
	HostCatalog             Type = 15
	HostSet                 Type = 16
	Host                    Type = 17
	Target                  Type = 18
	Global                  Type = 19

	// TODO: remove this after demo
	Group Type = 20
)

func (r Type) String() string {
	return [...]string{
		"unknown",
		"scope",
		"user",
		"static-group",
		"role",
		"org",
		"static-group-member",
		"static-group-user-member",
		"assigned-role",
		"assigned-user-role",
		"assigned-static-group-role",
		"role-grant",
		"auth-method",
		"project",
		"*",
		"host-catalog",
		"host-set",
		"host",
		"target",
		"global",
		"group",
	}[r]
}

var Map = map[string]Type{
	Scope.String():                   Scope,
	User.String():                    User,
	StaticGroup.String():             StaticGroup,
	Role.String():                    Role,
	Org.String():                     Org,
	StaticGroupMember.String():       StaticGroupMember,
	StaticGroupUserMember.String():   StaticGroupUserMember,
	AssignedRole.String():            AssignedRole,
	AssignedUserRole.String():        AssignedUserRole,
	AssignedStaticGroupRole.String(): AssignedStaticGroupRole,
	RoleGrant.String():               RoleGrant,
	AuthMethod.String():              AuthMethod,
	Project.String():                 Project,
	All.String():                     All,
	HostCatalog.String():             HostCatalog,
	HostSet.String():                 HostSet,
	Host.String():                    Host,
	Target.String():                  Target,
	Global.String():                  Global,
	Group.String():                   Group,
}
