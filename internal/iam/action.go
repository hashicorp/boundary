package iam

// Action defines a type for the Actions of Resources
type Action int

const (
	ActionUnknown Action = iota
	ActionAssignable
	ActionList
	ActionCreate
	ActionUpdate
	ActionEdit
	ActionDelete
)

func (a Action) String() string {
	return [...]string{
		"unknown",
		"assignable",
		"list",
		"create",
		"update",
		"edit",
		"delete"}[a]
}

// StdActions returns a standard set of actions for resources that support a CRUD API
func StdActions() map[string]Action {
	return map[string]Action{
		ActionAssignable.String(): ActionAssignable,
		ActionList.String():       ActionList,
		ActionCreate.String():     ActionCreate,
		ActionUpdate.String():     ActionUpdate,
		ActionEdit.String():       ActionEdit,
		ActionDelete.String():     ActionDelete,
	}
}
