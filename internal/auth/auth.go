package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/watchtower/internal/perms"
	"github.com/hashicorp/watchtower/internal/servers/controller/common"
	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"github.com/kr/pretty"
)

type key int

var verifierKey key

type RequestInfo struct {
	Path                 string
	Method               string
	PublicId             string
	Token                string
	DisableAuthzFailures bool
}

type verifier struct {
	logger          hclog.Logger
	iamRepoFn       common.IamRepoFactory
	authTokenRepoFn common.AuthTokenRepoFactory
	requestInfo     RequestInfo
	res             *perms.Resource
	act             action.Type
	ctx             context.Context
}

// NewVerifierContext creates a context that carries a verifier object from the
// HTTP handlers to the gRPC service handlers. It should only be created in the
// HTTP handler and should exist for every request that reaches the service
// handlers.
func NewVerifierContext(ctx context.Context,
	logger hclog.Logger,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	requestInfo RequestInfo) context.Context {
	return context.WithValue(ctx, verifierKey, &verifier{
		logger:          logger,
		iamRepoFn:       iamRepoFn,
		authTokenRepoFn: authTokenRepoFn,
		requestInfo:     requestInfo,
	})
}

// Verify takes in a context that has expected parameters as values and runs an
// authn/authz check. It returns a user ID, the scope ID for the request (which
// may come from the URL and may come from the token) and whether or not to
// proceed, e.g. whether the authn/authz check resulted in failure If an error
// occurs it's logged to the system log.
func Verify(ctx context.Context) (userId string, scopeId string, valid bool) {
	v, ok := ctx.Value(verifierKey).(*verifier)
	if !ok {
		// We don't have a logger yet and this should never happen in any
		// context we won't catch in tests
		panic("no verifier information found in context")
	}
	v.ctx = ctx
	if err := v.parseAuthParams(); err != nil {
		v.logger.Trace("error reading auth parameters from URL", "url", v.requestInfo.Path, "method", v.requestInfo.Method, "error", err)
		return
	}
	if v.res == nil {
		v.logger.Trace("got nil resource information after decorating auth parameters")
		return
	}

	authResults, userId, scopeId, err := v.performAuthCheck()
	if err != nil {
		v.logger.Error("error performing authn/authz check", "error", err)
		return
	}
	if !authResults.Allowed {
		// TODO: Decide whether to remove this
		if v.requestInfo.DisableAuthzFailures {
			v.logger.Info("failed authz info for request", "resource", pretty.Sprint(v.res), "user_id", userId, "action", v.act.String())
		} else {
			return
		}
	}

	valid = true
	return
}

func (v *verifier) parseAuthParams() error {
	// Remove trailing and leading slashes
	trimmedPath := strings.Trim(v.requestInfo.Path, "/")
	splitPath := strings.Split(strings.TrimPrefix(trimmedPath, "v1"), "/")
	splitLen := len(splitPath)
	if splitLen == 0 {
		return fmt.Errorf("parse auth params: invalid path")
	}

	var act action.Type
	var typStr string
	scp := scope.Global
	res := &perms.Resource{
		ScopeId: scope.Global.String(),
	}

	// Handle non-custom types. We'll deal with custom types, including list,
	// after parsing the path.
	switch v.requestInfo.Method {
	case "GET":
		act = action.Read
	case "POST":
		act = action.Create
	case "PATCH":
		act = action.Update
	case "DELETE":
		act = action.Delete
	default:
		return fmt.Errorf("parse auth params: unknown method %q", v.requestInfo.Method)
	}

	// Look for a custom action
	colonSplit := strings.Split(splitPath[splitLen-1], ":")
	switch len(colonSplit) {
	case 1:
		// No custom action specified
	case 2:
		actStr := colonSplit[len(colonSplit)-1]
		act = action.Map[actStr]
		if act == action.Unknown || act == action.All {
			return fmt.Errorf("parse auth params: unknown action %q", actStr)
		}
		// Keep going with the logic without the custom action
		splitPath[splitLen-1] = colonSplit[0]
	default:
		return fmt.Errorf("parse auth params: unexpected number of colons in last segment %q", colonSplit[len(colonSplit)-1])
	}

	// Walk backwards. As we walk backwards we look for scopes and figure out if
	// we're operating on a resource or a collection. We also populate the pin.
	// The rules for the pin are as follows:
	//
	// * If the last segment is a collection, the pin is the immediately
	// preceding ID
	//
	// * If the last segment is an ID, the pin is the immediately preceding ID
	// not including the last segment
	//
	// * If at the end of the logic the pin is the id of a scope ("global",
	// "o_...", "p_...") then there is no pin. The scopes are already enclosing
	// so a pin is redundant.
	nextIdIsPin := true
	for i := splitLen - 1; i >= 0; i-- {
		segment := splitPath[i]

		// Collections don't contain underscores; every resource ID does.
		segmentIsCollection := !strings.Contains(segment, "_")

		if !segmentIsCollection && i != splitLen-1 && nextIdIsPin {
			res.Pin = segment
			nextIdIsPin = false
		}

		// Update the scope. Set it to org only if it's at global (that way we
		// don't override project with org). We have to check if it's one less
		// than the length of the split because operating on the id of a scope
		// is actually in the enclosing scope (since you're in the parent scope
		// operating on a child scope).
		switch segment {
		case "projects":
			if i < splitLen-2 {
				scp = scope.Project
				res.ScopeId = splitPath[i+1]
			}
		case "orgs":
			if scp == scope.Global {
				if i < splitLen-2 {
					scp = scope.Org
					res.ScopeId = splitPath[i+1]
				}
			}
		}

		if segment == "" {
			// This could be the case if we have an action like
			// /orgs/o_1234/projects/p_1234/:set-defaults to act on the project
			// itself but within its own scope
			continue
		}

		if typStr == "" {
			// The resource check takes place inside the type check because if
			// we've identified the type we have either already identified the
			// right-most resource ID or we're operating on a collection, so
			// this prevents us from finding a different ID earlier in the path.
			//
			// We continue on with the enclosing loop anyways though to ensure
			// we find the right scope.
			if res.Id == "" && !segmentIsCollection {
				res.Id = segment
			} else {
				// Every collection is the plural of the resource type so drop
				// the last 's'
				if !strings.HasSuffix(segment, "s") {
					return fmt.Errorf("parse auth params: invalid collection syntax for %q", segment)
				}
				typStr = strings.TrimSuffix(segment, "s")
			}
		}
	}

	if typStr != "" {
		res.Type = resource.Map[typStr]
		if res.Type == resource.Unknown {
			return fmt.Errorf("parse auth params: unknown resource type %q", typStr)
		}
	} else if res.Id == "" {
		return errors.New("parse auth params: id and type both not found")
	}

	// If we're operating on a collection (that is, the ID is blank) and it's a
	// GET, it's actually a list
	if res.Id == "" && act == action.Read {
		act = action.List
	}

	// If the pin ended up being a scope, nil it out
	if res.Pin != "" {
		if res.Pin == "global" ||
			strings.HasPrefix(res.Pin, "o_") ||
			strings.HasPrefix(res.Pin, "p_") {
			res.Pin = ""
		}
	}

	v.res = res
	v.act = act
	return nil
}

func (v verifier) performAuthCheck() (aclResults *perms.ACLResults, userId, scopeId string, retErr error) {
	// Ensure we return an error by default if we forget to set this somewhere
	retErr = errors.New("unknown")
	userId = "u_anon"
	scopeId = v.res.ScopeId

	// Validate the token and fetch the corresponding user ID
	tokenRepo, err := v.authTokenRepoFn()
	if err != nil {
		retErr = fmt.Errorf("perform auth check: failed to get authtoken repo: %w", err)
		return
	}

	at, err := tokenRepo.ValidateToken(v.ctx, v.requestInfo.PublicId, v.requestInfo.Token)
	if err != nil {
		retErr = fmt.Errorf("perform auth check: failed to validate token: %w", err)
		return
	}
	if at != nil {
		userId = at.GetIamUserId()
	}

	var parsedGrants []perms.Grant
	var grantPairs []perms.GrantPair

	// Fetch and parse grants for this user ID (which may include grants for
	// u_anon and u_auth)
	iamRepo, err := v.iamRepoFn()
	if err != nil {
		retErr = fmt.Errorf("perform auth check: failed to get iam repo: %w", err)
		return
	}
	grantPairs, err = iamRepo.GrantsForUser(v.ctx, userId)
	if err != nil {
		retErr = fmt.Errorf("perform auth check: failed to query for user grants: %w", err)
		return
	}
	parsedGrants = make([]perms.Grant, 0, len(grantPairs))
	for _, pair := range grantPairs {
		parsed, err := perms.Parse(pair.ScopeId, userId, pair.Grant)
		if err != nil {
			retErr = fmt.Errorf("perform auth check: failed to parse grant %#v: %w", pair.Grant, err)
			return
		}
		parsedGrants = append(parsedGrants, parsed)
	}

	// TODO: When we migrate to scopes, the resource scope ID for this check and
	// in the return value needs to be adjusted to the token scope ID for
	// actions within the scopes collection
	acl := perms.NewACL(parsedGrants...)
	allowed := acl.Allowed(*v.res, v.act)

	aclResults = &allowed
	retErr = nil
	return
}
