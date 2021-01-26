package scopeids

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// GetScopeIds, given common parameters for List calls, returns the set of scope
// IDs in which to search for resources. It also returns a memoized map of the
// scopes to their info for populating returned values.
//
// Note: This was originally pulled out 1:1 from the role service. It and other
// tests in the other service handlers test this function extensively as it
// forms the basis for all recursive listing tests; see those tests for list
// functionality in the various service handlers.
func GetScopeIds(
	// The context to use when listing in the DB, if required
	ctx context.Context,
	// An IAM repo function to use for a listing call, if required
	repoFn common.IamRepoFactory,
	// The original auth results from the list command
	authResults auth.VerifyResults,
	// The scope ID to use, or to use as the starting point for a recursive
	// search
	rootScopeId string,
	// Whether or not the search should be recursive
	recursive bool) ([]string, map[string]*scopes.ScopeInfo, error) {
	// Get the list of scope IDs. If it's recursive, check ACLs.
	var scopeIds []string
	// This will be used to memoize scope info so we can put the right scope
	// info for each returned value
	scopeInfoMap := map[string]*scopes.ScopeInfo{
		rootScopeId: authResults.Scope,
	}
	switch recursive {
	case true:
		repo, err := repoFn()
		if err != nil {
			return nil, nil, err
		}
		// Get all scopes recursively
		scps, err := repo.ListScopesRecursively(ctx, rootScopeId)
		if err != nil {
			return nil, nil, err
		}
		scopeIds = make([]string, 0, len(scps))
		res := perms.Resource{
			Type: resource.Role,
		}
		// For each scope, see if we have permission to list on that scope
		for _, scp := range scps {
			scpId := scp.GetPublicId()
			// We already checked the incoming ID so we can definitely add it
			if scpId == authResults.Scope.Id {
				scopeIds = append(scopeIds, scp.GetPublicId())
				continue
			}
			res.ScopeId = scpId
			aSet := authResults.FetchActionSetForType(ctx,
				resource.Role,
				action.ActionSet{action.List},
				auth.WithResource(&res),
			)
			// We only passed one action in, so anything other than that one
			// action back should not be included. Assuming it's correct, add
			// the scope ID for lookup and memoize the scope info if needed.
			if len(aSet) == 1 && aSet[0] == action.List {
				scopeIds = append(scopeIds, scpId)
				if scopeInfoMap[scpId] == nil {
					scopeInfo := &scopes.ScopeInfo{
						Id:          scp.GetPublicId(),
						Type:        scp.GetType(),
						Name:        scp.GetName(),
						Description: scp.GetDescription(),
					}
					scopeInfoMap[scpId] = scopeInfo
				}
			}
		}

	default:
		scopeIds = []string{rootScopeId}
	}

	return scopeIds, scopeInfoMap, nil
}
