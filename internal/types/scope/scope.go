package scope

// Type defines the possible types for Scopes
type Type uint

const (
	Unknown Type = 0
	Global  Type = 1
	Org     Type = 2
	Project Type = 3
)

func (s Type) String() string {
	return [...]string{
		"unknown",
		"global",
		"org",
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

var Map = map[string]Type{
	Global.String():  Global,
	Org.String():     Org,
	Project.String(): Project,
}
