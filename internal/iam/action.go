package iam

// Action defines a type for the Actions of Resources
// actions are also stored as a lookup db table named iam_action
type Action int

// not using iota intentionally, since the values are stored in the db as well.
const (
	ActionUnknown Action = 0
	ActionList    Action = 1
	ActionCreate  Action = 2
	ActionUpdate  Action = 3
	ActionRead    Action = 4
	ActionDelete  Action = 5
	ActionAuthen  Action = 6
	ActionAll     Action = 7
	ActionConnect Action = 8
)

func (a Action) String() string {
	return [...]string{
		"unknown",
		"list",
		"create",
		"update",
		"read",
		"delete",
		"authen",
		"all",
		"connect",
	}[a]
}

// CrudActions returns a standard set of actions for resources that support a CRUD API
func CrudActions() map[string]Action {
	return map[string]Action{
		ActionList.String():   ActionList,
		ActionCreate.String(): ActionCreate,
		ActionUpdate.String(): ActionUpdate,
		ActionRead.String():   ActionRead,
		ActionDelete.String(): ActionDelete,
	}
}
