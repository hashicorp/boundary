package scopeids

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
)

type authzProtectedEntityProvider interface {
	// Fetches basic resource info for the given scopes. Note that this is a
	// "where clause" style of argument: if the set of scopes is populated these
	// are the scopes to limit to (e.g. to put in a where clause). An empty set
	// of scopes means to look in *all* scopes, not none!
	FetchAuthzProtectedEntitiesByScope(ctx context.Context, projectIds []string) (map[string][]boundary.AuthzProtectedEntity, error)
}

// ResourceInfo contains information about a particular resource
type ResourceInfo struct {
	AuthorizedActions action.ActionSet
}

// ScopeInfoWithResourceIds contains information about a scope and the resources
// found within it
type ScopeInfoWithResourceIds struct {
	*scopes.ScopeInfo
	Resources map[string]ResourceInfo
}

// GetListingResourceInformationInput contains input parameters to the function
type GetListingResourceInformationInput struct {
	// An IAM repo function to use for a scope listing call
	IamRepoFn common.IamRepoFactory

	// The original auth results from the list command
	AuthResults auth.VerifyResults

	// The scope ID to use, or the starting point for a recursive search
	RootScopeId string

	// The type of resource being listed
	Type resource.Type

	// Whether the search is recursive
	Recursive bool

	// A repo to fetch resources
	AuthzProtectedEntityProvider authzProtectedEntityProvider

	// The available actions for the resource type
	ActionSet action.ActionSet
}

// GetListingResourceInformationOutput contains results from the function
type GetListingResourceInformationOutput struct {
	// The calculated list of relevant scope IDs
	ScopeIds []string

	// The specific resource IDs calculated to be authorized for listing
	ResourceIds []string

	// A map of scope ID to scope information and a map of resource IDs in that
	// scope and specific information about that resource, such as available
	// actions
	ScopeResourceMap map[string]*ScopeInfoWithResourceIds
}

// GetListingResourceInformation, given common parameters for List calls,
// returns useful information: the set of scope IDs in which to search for
// resources; the IDs of the resources known to be authorized for that user; and
// a memoized map of the scopes to their info for populating returned values.
func GetListingResourceInformation(
	// The context to use when listing in the DB, if required
	ctx context.Context,
	// The input struct
	input GetListingResourceInformationInput,
) (*GetListingResourceInformationOutput, error) {
	const op = "scopeids.GetListingResourceInformation"

	output := new(GetListingResourceInformationOutput)

	// Validation
	switch {
	case input.Type == resource.Unknown:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unknown resource")
	case input.IamRepoFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil iam repo")
	case input.RootScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root scope id")
	case input.AuthResults.Scope == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil scope in auth results")
	case !input.Recursive && input.AuthResults.Scope.Id != input.RootScopeId:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "non-recursive search but auth results scope does not match root scope")
	}

	// This will be used to memoize scope info so we can put the right scope
	// info for each returned value
	output.ScopeResourceMap = map[string]*ScopeInfoWithResourceIds{}

	// Base case: if not recursive, return the scope we were given and the
	// already-looked-up info
	if !input.Recursive {
		output.ScopeResourceMap[input.AuthResults.Scope.Id] = &ScopeInfoWithResourceIds{ScopeInfo: input.AuthResults.Scope}
		// If we don't have information do to the resource lookup ourselves,
		// return what we have
		if input.AuthzProtectedEntityProvider == nil {
			output.ScopeIds = []string{input.AuthResults.Scope.Id}
			return output, nil
		}
		// Otherwise filter on this one scope and return
		if err := filterAuthorizedResourceIds(ctx, input, output); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error filtering to only authorized resources"))
		}
		return output, nil
	}

	repo, err := input.IamRepoFn()
	if err != nil {
		return nil, err
	}
	// Get all scopes recursively. Start at global because we need to take into
	// account permissions in parent scopes even if they want to scale back the
	// returned information to a child scope and its children.
	scps, err := repo.ListScopesRecursively(ctx, scope.Global.String())
	if err != nil {
		return nil, err
	}

	res := perms.Resource{
		Type: input.Type,
	}
	// For each scope, see if we have permission to list that type in that
	// scope
	var deferredScopes []*iam.Scope
	// Store whether global has list permission
	var globalHasList bool
	for _, scp := range scps {
		scpId := scp.GetPublicId()
		res.ScopeId = scpId
		aSet := input.AuthResults.FetchActionSetForType(ctx,
			// This is overridden by WithResource
			resource.Unknown,
			action.ActionSet{action.List},
			auth.WithResource(&res),
		)
		switch len(aSet) {
		case 0:
			// Defer until we've read all scopes. We do this because if the
			// ordering coming back isn't in parent-first ordering our map
			// lookup might fail.
			deferredScopes = append(deferredScopes, scp)
		case 1:
			if aSet[0] != action.List {
				return nil, errors.New(ctx, errors.Internal, op, "unexpected action in set")
			}
			if output.ScopeResourceMap[scpId] == nil {
				scopeInfo := &scopes.ScopeInfo{
					Id:            scp.GetPublicId(),
					Type:          scp.GetType(),
					Name:          scp.GetName(),
					Description:   scp.GetDescription(),
					ParentScopeId: scp.GetParentId(),
				}
				output.ScopeResourceMap[scpId] = &ScopeInfoWithResourceIds{ScopeInfo: scopeInfo}
			}
			if scpId == scope.Global.String() {
				globalHasList = true
			}
		default:
			return nil, errors.New(ctx, errors.Internal, op, "unexpected number of actions back in set")
		}
	}

	// Now go through these and see if a parent matches
	for _, scp := range deferredScopes {
		// If they had list on global scope anything else is automatically
		// included; otherwise if they had list on the parent scope, this
		// scope is included in the map and is sufficient here.
		if globalHasList || output.ScopeResourceMap[scp.GetParentId()] != nil {
			scpId := scp.GetPublicId()
			if output.ScopeResourceMap[scpId] == nil {
				scopeInfo := &scopes.ScopeInfo{
					Id:            scp.GetPublicId(),
					Type:          scp.GetType(),
					Name:          scp.GetName(),
					Description:   scp.GetDescription(),
					ParentScopeId: scp.GetParentId(),
				}
				output.ScopeResourceMap[scpId] = &ScopeInfoWithResourceIds{ScopeInfo: scopeInfo}
			}
		}
	}

	// Now elide out any that aren't under the root scope ID
	elideScopes := make([]string, 0, len(output.ScopeResourceMap))
	for scpId, scp := range output.ScopeResourceMap {
		switch input.RootScopeId {
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
		delete(output.ScopeResourceMap, scpId)
	}

	// If we have nothing in scopeInfoMap at this point, we aren't authorized
	// anywhere so return 403.
	if len(output.ScopeResourceMap) == 0 {
		return nil, handlers.ForbiddenError()
	}

	if input.AuthzProtectedEntityProvider == nil {
		output.populateScopeIdsFromScopeResourceMap()
		return output, nil
	}

	if err := filterAuthorizedResourceIds(ctx, input, output); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error filtering to only authorized resources"))
	}

	return output, nil
}

// filterAuthorizedResourceIds calls the passed in function to get IDs for
// resources in the given scopes and then figures out which ones are actually
// authorized for listing by the user.
//
// It also populates the scope IDs in the output
func filterAuthorizedResourceIds(
	// The context to use when listing in the DB, if required
	ctx context.Context,
	// The input struct
	input GetListingResourceInformationInput,
	// The scope information to fill out
	output *GetListingResourceInformationOutput,
) error {
	const op = "scopeids.filterAuthorizedResources"

	// Populate scopeIds and determine if we found global
	output.populateScopeIdsFromScopeResourceMap()

	// The calling function is giving us a complete set with any recursive
	// lookup already performed (that's the point of the function).
	scopedResourceInfo, err := input.AuthzProtectedEntityProvider.FetchAuthzProtectedEntitiesByScope(ctx, output.ScopeIds)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	res := perms.Resource{
		Type: input.Type,
	}

	// Now run authorization checks against each so we know if there is a point
	// in fetching the full resource, and cache the authorized actions
	for scopeId, resourceInfos := range scopedResourceInfo {
		for _, resourceInfo := range resourceInfos {
			res.Id = resourceInfo.GetPublicId()
			res.ScopeId = scopeId
			authorizedActions := input.AuthResults.FetchActionSetForId(ctx, resourceInfo.GetPublicId(), input.ActionSet, auth.WithResource(&res))
			if len(authorizedActions) == 0 {
				continue
			}

			if resourceInfo.GetUserId() != "" {
				if authorizedActions.OnlySelf() && resourceInfo.GetUserId() != input.AuthResults.UserData.User.Id {
					continue
				}
			}

			if output.ScopeResourceMap[scopeId] == nil {
				return errors.New(ctx, errors.Internal, op, fmt.Sprintf("scope id %s returned from fetching authz protected entities not found in scope resource map", scopeId))
			}
			if output.ScopeResourceMap[scopeId].Resources == nil {
				output.ScopeResourceMap[scopeId].Resources = make(map[string]ResourceInfo)
			}

			output.ScopeResourceMap[scopeId].Resources[resourceInfo.GetPublicId()] = ResourceInfo{AuthorizedActions: authorizedActions}
			output.ResourceIds = append(output.ResourceIds, resourceInfo.GetPublicId())
		}
	}

	return nil
}

// populateScopeIdsFromScopeResourceMap populates the ScopeIds field and returns
// whether global scope was found
func (i *GetListingResourceInformationOutput) populateScopeIdsFromScopeResourceMap() {
	for k := range i.ScopeResourceMap {
		i.ScopeIds = append(i.ScopeIds, k)
	}
}

// GetListingScopeIds is provided for backwards compatibility with existing
// services; services should eventually migrate to
// GetListingResourceInformation.
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
) ([]string, map[string]*scopes.ScopeInfo, error) {
	const op = "scopeids.GetListingScopeIds"
	scopeResourceInfo, err := GetListingResourceInformation(ctx,
		GetListingResourceInformationInput{
			IamRepoFn:   repoFn,
			AuthResults: authResults,
			RootScopeId: rootScopeId,
			Type:        typ,
			Recursive:   recursive,
		},
	)
	if err != nil {
		if err == handlers.ForbiddenError() {
			return nil, nil, err
		}
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	if len(scopeResourceInfo.ScopeIds) == 0 {
		// This should have already happened in the other function, but...
		return nil, nil, handlers.ForbiddenError()
	}
	scopeMap := make(map[string]*scopes.ScopeInfo, len(scopeResourceInfo.ScopeResourceMap))
	for k, v := range scopeResourceInfo.ScopeResourceMap {
		scopeMap[k] = v.ScopeInfo
	}
	return scopeResourceInfo.ScopeIds, scopeMap, nil
}
