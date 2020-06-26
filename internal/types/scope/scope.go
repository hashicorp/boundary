package scope

// Type defines the possible types for Scopes
type Type uint32

const (
	Unknown      Type = 0
	Organization Type = 1
	Project      Type = 2
)

func (s Type) String() string {
	return [...]string{
		"unknown",
		"organization",
		"project",
	}[s]
}

func (s Type) Prefix() string {
	return [...]string{
		"unknown",
		"o",
		"p",
	}[s]
}

func StringToScopeType(s string) Type {
	switch s {
	case Organization.String():
		return Organization
	case Project.String():
		return Project
	default:
		return Unknown
	}
}
