package action

// Type defines a type for the Actions of Resources
// actions are also stored as a lookup db table named iam_action
type Type int

// not using iota intentionally, since the values are stored in the db as well.
const (
	Unknown Type = 0
	List    Type = 1
	Create  Type = 2
	Update  Type = 3
	Read    Type = 4
	Delete  Type = 5
	Authen  Type = 6
	All     Type = 7
	Connect Type = 8
)

var Map = map[string]Type{
	"unknown": Unknown,
	"list":    List,
	"create":  Create,
	"update":  Update,
	"read":    Read,
	"delete":  Delete,
	"authen":  Authen,
	"*":       All,
	"connect": Connect,
}

func (a Type) String() string {
	return [...]string{
		"unknown",
		"list",
		"create",
		"update",
		"read",
		"delete",
		"authen",
		"*",
		"connect",
	}[a]
}
