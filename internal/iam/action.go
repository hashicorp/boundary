package iam

// Action defines a type for the Actions of Resources
// actions are also stored as a lookup db table named iam_action
type Action int

const (
	ActionUnknown Action = 0
	ActionList    Action = 1
	ActionCreate  Action = 2
	ActionUpdate  Action = 3
	ActionEdit    Action = 4
	ActionDelete  Action = 5
	ActionAuthen  Action = 6
)

func (a Action) String() string {
	return [...]string{
		"unknown",
		"list",
		"create",
		"update",
		"edit",
		"delete",
		"authen",
	}[a]
}

// StdActions returns a standard set of actions for resources that support a CRUD API
func StdActions() map[string]Action {
	return map[string]Action{
		ActionList.String():   ActionList,
		ActionCreate.String(): ActionCreate,
		ActionUpdate.String(): ActionUpdate,
		ActionEdit.String():   ActionEdit,
		ActionDelete.String(): ActionDelete,
	}
}
