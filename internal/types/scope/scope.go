package scope

// Type defines the possible types for Scopes
type Type uint32

const (
	Unknown      Type = 0
	Msp          Type = 1
	Organization Type = 2
	Project      Type = 3
)

func (s Type) String() string {
	return [...]string{
		"unknown",
		"msp",
		"organization",
		"project",
	}[s]
}

func (s Type) Prefix() string {
	return [...]string{
		"unknown",
		"msp",
		"o",
		"p",
	}[s]
}

func StringToScopeType(s string) Type {
	switch s {
	case Msp.String():
		return Msp
	case Organization.String():
		return Organization
	case Project.String():
		return Project
	default:
		return Unknown
	}
}
