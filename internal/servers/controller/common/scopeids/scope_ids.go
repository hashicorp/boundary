package scopeids

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// GetListingScopeIds, given common parameters for List calls, returns the set of scope
// IDs in which to search for resources. It also returns a memoized map of the
// scopes to their info for populating returned values.
//
// Note: This was originally pulled out 1:1 from the role service. It and other
// tests in the other service handlers test this function extensively as it
// forms the basis for all recursive listing tests; see those tests for list
// functionality in the various service handlers.
func GetListingScopeIds(
	// The context to use when listing in the DB, if required
	ctx context.Context,
	// An IAM repo function to use for a listing call, if required
	repoFn common.IamRepoFactory,
	// The original auth results from the list command
	authResults auth.VerifyResults,
	// The scope ID to use, or to use as the starting point for a recursive
	// search
	rootScopeId string,
	// The type of resource we are listing
	typ resource.Type,
	// Whether or not the search should be recursive
	recursive bool,
	// Whether to only return scopes with exact permissions, or whether parent
	// scopes with appropriate permissions are sufficient
	directOnly bool) ([]string, map[string]*scopes.ScopeInfo, error) {
	const op = "GetListingScopeIds"
	switch {
	case typ == resource.Unknown:
		return nil, nil, errors.New(errors.InvalidParameter, op, "unknown resource")
	case repoFn == nil:
		return nil, nil, errors.New(errors.InvalidParameter, op, "nil iam repo")
	case rootScopeId == "":
		return nil, nil, errors.New(errors.InvalidParameter, op, "missing root scope id")
	case authResults.Scope == nil:
		return nil, nil, errors.New(errors.InvalidParameter, op, "nil scope in auth results")
	}
	// Get the list of scope IDs. If it's recursive, check ACLs.
	var scopeIds []string
	// This will be used to memoize scope info so we can put the right scope
	// info for each returned value
	scopeInfoMap := map[string]*scopes.ScopeInfo{}
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
			Type: typ,
		}
		// For each scope, see if we have permission to list that type in that
		// scope
		var deferredScopes []*iam.Scope
		// Store whether global was a part of the lookup and it has list
		// permission
		var globalHasList bool
		for _, scp := range scps {
			scpId := scp.GetPublicId()
			res.ScopeId = scpId
			aSet := authResults.FetchActionSetForType(ctx,
				// This is overridden by WithResource
				resource.Unknown,
				action.ActionSet{action.List},
				auth.WithResource(&res),
			)
			switch len(aSet) {
			case 0:
				// Defer until we've read all scopes. We do this because if the
				// ordering coming back isn't in parent-first ording our map
				// lookup might fail.
				if !directOnly {
					deferredScopes = append(deferredScopes, scp)
				}
			case 1:
				if aSet[0] != action.List {
					return nil, nil, errors.New(errors.Internal, op, "unexpected action in set")
				}
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
				if scpId == "global" {
					globalHasList = true
				}
			default:
				return nil, nil, errors.New(errors.Internal, op, "unexpected number of actions back in set")
			}
		}
		// Now go through these and see if a parent matches
		for _, scp := range deferredScopes {
			// If they had list on global scope anything else is automatically
			// included; otherwise if they had list on the parent scope, this
			// scope is included.
			if globalHasList || scopeInfoMap[scp.GetParentId()] != nil {
				scpId := scp.GetPublicId()
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
