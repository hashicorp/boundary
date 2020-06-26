package resource

// Type defines the types of resources in the system
type Type int

const (
	Unknown                 Type = 0
	Scope                   Type = 1
	User                    Type = 2
	StaticGroup             Type = 3
	Role                    Type = 4
	Organization            Type = 5
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
)

func (r Type) String() string {
	return [...]string{
		"unknown",
		"scope",
		"user",
		"static-group",
		"role",
		"organization",
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
	}[r]
}

func StringToResourceType(s string) Type {
	switch s {
	case Scope.String():
		return Scope
	case User.String():
		return User
	case StaticGroup.String():
		return StaticGroup
	case Role.String():
		return Role
	case Organization.String():
		return Organization
	case StaticGroupMember.String():
		return StaticGroupMember
	case StaticGroupUserMember.String():
		return StaticGroupUserMember
	case AssignedRole.String():
		return AssignedRole
	case AssignedUserRole.String():
		return AssignedRole
	case AssignedStaticGroupRole.String():
		return AssignedStaticGroupRole
	case RoleGrant.String():
		return RoleGrant
	case AuthMethod.String():
		return AuthMethod
	case Project.String():
		return Project
	case All.String():
		return All
	case HostCatalog.String():
		return HostCatalog
	case HostSet.String():
		return HostSet
	case Host.String():
		return Host
	case Target.String():
		return Target
	default:
		return Unknown
	}
}
