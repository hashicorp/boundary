package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/boundary"
)

type listForAuthzCheckFunc func(ctx context.Context, projectIds []string) (map[string][]boundary.AuthzProtectedEntity, error)

func (a listForAuthzCheckFunc) FetchAuthzProtectedEntitiesByScope(ctx context.Context, projectIds []string) (map[string][]boundary.AuthzProtectedEntity, error) {
	return a(ctx, projectIds)
}

// ListForAuthzCheck returns a functions that fetches sessions for the given
// projects. Note that the sessions are not fully populated, and only contain the
// necessary information to implement the boundary.AuthzProtectedEntity
// interface. Supports the WithTerminated option.
func ListForAuthzCheck(repo *Repository, opt ...Option) listForAuthzCheckFunc {
	return func(ctx context.Context, projectIds []string) (map[string][]boundary.AuthzProtectedEntity, error) {
		return repo.fetchAuthzProtectedSessionsByProject(ctx, projectIds, opt...)
	}
}
