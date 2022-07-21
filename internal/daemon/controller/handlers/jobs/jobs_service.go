package jobs

import (
	"github.com/hashicorp/boundary/internal/types/action"
)

var (
	// CollectionActions contains the set of actions that can be performed on
	// this collection.
	CollectionActions = action.ActionSet{
		action.Read,
		action.List,
		action.StopJob,
	}
)

// Service implements the jobs service.
type Service struct {
}

// NewService returns a new jobs service.
func NewService() (Service, error) {
	return Service{}, nil
}
