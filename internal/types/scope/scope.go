package scope

// Type defines the possible types for Scopes
type Type uint32

const (
	Unknown      Type = 0
	Global       Type = 1
	Organization Type = 2
	Project      Type = 3
)

func (s Type) String() string {
	return [...]string{
		"unknown",
		"global",
		"organization",
		"project",
	}[s]
}

func (s Type) Prefix() string {
	return [...]string{
		"unknown",
		"global",
		"o",
		"p",
	}[s]
}

func StringToScopeType(s string) Type {
	switch s {
	case Global.String():
		return Global
	case Organization.String():
		return Organization
	case Project.String():
		return Project
	default:
		return Unknown
	}
}
