package action

// Type defines a type for the Actions of Resources
// actions are also stored as a lookup db table named iam_action
type Type int

// not using iota intentionally, since the values are stored in the db as well.
const (
	Unknown          Type = 0
	List             Type = 1
	Create           Type = 2
	Update           Type = 3
	Read             Type = 4
	Delete           Type = 5
	Authenticate     Type = 6
	All              Type = 7
	Connect          Type = 8
	AddGrants        Type = 9
	RemoveGrants     Type = 10
	SetGrants        Type = 11
	AddPrincipals    Type = 12
	SetPrincipals    Type = 13
	RemovePrincipals Type = 14
)

var Map = map[string]Type{
	"list":              List,
	"create":            Create,
	"update":            Update,
	"read":              Read,
	"delete":            Delete,
	"authenticate":      Authenticate,
	"*":                 All,
	"connect":           Connect,
	"add-grants":        AddGrants,
	"remove-grants":     RemoveGrants,
	"set-grants":        SetGrants,
	"add-principals":    AddPrincipals,
	"set-principals":    SetPrincipals,
	"remove-principals": RemovePrincipals,
}

func (a Type) String() string {
	return [...]string{
		"unknown",
		"list",
		"create",
		"update",
		"read",
		"delete",
		"authenticate",
		"*",
		"connect",
		"add-grants",
		"remove-grants",
		"set-grants",
		"add-principals",
		"set-principals",
		"remove-principals",
	}[a]
}
