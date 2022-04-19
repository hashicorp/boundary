package scopeids

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
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
	directOnly bool,
) ([]string, map[string]*scopes.ScopeInfo, error) {
	const op = "GetListingScopeIds"

	// Validation
	switch {
	case typ == resource.Unknown:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "unknown resource")
	case repoFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil iam repo")
	case rootScopeId == "":
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing root scope id")
	case authResults.Scope == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil scope in auth results")
	}

	// Base case: if not recursive, return the scope we were given and the
	// already-looked-up info
	if !recursive {
		return []string{authResults.Scope.Id}, map[string]*scopes.ScopeInfo{authResults.Scope.Id: authResults.Scope}, nil
	}

	// This will be used to memoize scope info so we can put the right scope
	// info for each returned value
	scopeInfoMap := map[string]*scopes.ScopeInfo{}

	repo, err := repoFn()
	if err != nil {
		return nil, nil, err
	}
	// Get all scopes recursively. Start at global because we need to take into
	// account permissions in parent scopes even if they want to scale back the
	// returned information to a child scope and its children.
	scps, err := repo.ListScopesRecursively(ctx, scope.Global.String())
	if err != nil {
		return nil, nil, err
	}

	res := perms.Resource{
		Type: typ,
	}
	// For each scope, see if we have permission to list that type in that
	// scope
	var deferredScopes []*iam.Scope
	// Store whether global has list permission
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
				return nil, nil, errors.New(ctx, errors.Internal, op, "unexpected action in set")
			}
			if scopeInfoMap[scpId] == nil {
				scopeInfo := &scopes.ScopeInfo{
					Id:            scp.GetPublicId(),
					Type:          scp.GetType(),
					Name:          scp.GetName(),
					Description:   scp.GetDescription(),
					ParentScopeId: scp.GetParentId(),
				}
				scopeInfoMap[scpId] = scopeInfo
			}
			if scpId == scope.Global.String() {
				globalHasList = true
			}
		default:
			return nil, nil, errors.New(ctx, errors.Internal, op, "unexpected number of actions back in set")
		}
	}

	// Now go through these and see if a parent matches
	for _, scp := range deferredScopes {
		// If they had list on global scope anything else is automatically
		// included; otherwise if they had list on the parent scope, this
		// scope is included in the map and is sufficient here.
		if globalHasList || scopeInfoMap[scp.GetParentId()] != nil {
			scpId := scp.GetPublicId()
			if scopeInfoMap[scpId] == nil {
				scopeInfo := &scopes.ScopeInfo{
					Id:            scp.GetPublicId(),
					Type:          scp.GetType(),
					Name:          scp.GetName(),
					Description:   scp.GetDescription(),
					ParentScopeId: scp.GetParentId(),
				}
				scopeInfoMap[scpId] = scopeInfo
			}
		}
	}

	// If we have nothing in scopeInfoMap at this point, we aren't authorized
	// anywhere so return 403.
	if len(scopeInfoMap) == 0 {
		return nil, nil, handlers.ForbiddenError()
	}

	// Now elide out any that aren't under the root scope ID
	elideScopes := make([]string, 0, len(scopeInfoMap))
	for scpId, scp := range scopeInfoMap {
		switch rootScopeId {
		// If the root is global, it matches
		case scope.Global.String():
		// If the current scope matches the root, it matches
		case scpId:
		// Or if the parent of this scope is the root (for orgs that would mean
		// a root scope ID which is covered in the case above, so this is really
		// projects matching an org used as the root)
		case scp.GetParentScopeId():
		default:
			elideScopes = append(elideScopes, scpId)
		}
	}

	for _, scpId := range elideScopes {
		delete(scopeInfoMap, scpId)
	}

	scopeIds := make([]string, 0, len(scopeInfoMap))
	for k := range scopeInfoMap {
		scopeIds = append(scopeIds, k)
	}

	return scopeIds, scopeInfoMap, nil
}
