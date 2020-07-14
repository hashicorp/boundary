package iam

import "github.com/hashicorp/watchtower/internal/types/action"

// CrudActions returns a standard set of actions for resources that support a CRUD API
func CrudActions() map[string]action.Type {
	return map[string]action.Type{
		action.Create.String(): action.Create,
		action.Update.String(): action.Update,
		action.Read.String():   action.Read,
		action.Delete.String(): action.Delete,
	}
}

// CrudlActions adds list to the standard set of actions for resources that support a CRUD API
func CrudlActions() map[string]action.Type {
	return map[string]action.Type{
		action.Create.String(): action.Create,
		action.Update.String(): action.Update,
		action.Read.String():   action.Read,
		action.Delete.String(): action.Delete,
		action.List.String():   action.List,
	}
}
