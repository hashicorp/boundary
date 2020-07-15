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
	"github.com/kr/pretty"
)

type key int

var verifierKey key

// RequestInfo contains request parameters necessary for checking authn/authz
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
// proceed, e.g. whether the authn/authz check resulted in failure. If an error
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
	// Remove `v1/`
	splitPath := strings.Split(strings.TrimPrefix(trimmedPath, "v1/"), "/")
	splitLen := len(splitPath)

	// It must be at least length 1 and the first segment must be "scopes"
	switch {
	case splitLen == 0:
		return fmt.Errorf("parse auth params: invalid path")
	case splitPath[0] != "scopes":
		return fmt.Errorf("parse auth params: invalid first segment %q", splitPath[0])
	}

	v.act = action.Unknown
	v.res = &perms.Resource{
		// Start out with scope, and replace when we walk backwards if it's
		// actually something else
		Type: resource.Scope,
	}

	// Handle non-custom types. We'll deal with custom types, including list,
	// after parsing the path.
	switch v.requestInfo.Method {
	case "GET":
		v.act = action.Read
	case "POST":
		v.act = action.Create
	case "PATCH":
		v.act = action.Update
	case "DELETE":
		v.act = action.Delete
	default:
		return fmt.Errorf("parse auth params: unknown method %q", v.requestInfo.Method)
	}

	// Look for a custom action
	colonSplit := strings.Split(splitPath[splitLen-1], ":")
	switch len(colonSplit) {
	case 1:
		// No custom action specified

	case 2:
		// Parse and validate the action, then elide it
		actStr := colonSplit[len(colonSplit)-1]
		v.act = action.Map[actStr]
		if v.act == action.Unknown || v.act == action.All {
			return fmt.Errorf("parse auth params: unknown action %q", actStr)
		}
		// Keep going with the logic without the custom action
		splitPath[splitLen-1] = colonSplit[0]

	default:
		return fmt.Errorf("parse auth params: unexpected number of colons in last segment %q", colonSplit[len(colonSplit)-1])
	}

	// Get scope information and handle it in a special case; that is, for
	// operating on scopes, we use the token scope, not the path scope
	switch splitLen {
	case 1:
		// We've already validated that this is "scopes"
		if v.act == action.Read {
			v.act = action.List
		}
		// We're operating on the scopes collection. Set the scope ID to
		// "scopes", which will be a signal to read it from the token.
		v.res.ScopeId = "scopes"
		return nil

	case 2:
		// The next segment should be the scope ID, and we still need to look up
		// the actual request scopefrom the token like in the case above.
		v.res.ScopeId = "scopes"
		v.res.Id = splitPath[1]
		return nil

	case 3:
		// If a custom action was being performed within a scope, it will have
		// been elided above. If the last path segment is now empty, address
		// this scenario. In this case the action took place _in_ the scope so
		// it should be bound accordingly. (This is for actions like
		// /scopes/o_abc/:deauthenticate where the action is _in_ the scope, not
		// on the scope.)
		if splitPath[2] == "" {
			v.res.ScopeId = splitPath[1]
			v.res.Id = splitPath[1]
			return nil
		}

		fallthrough

	default:
		// In all other cases the scope ID is the next segment
		v.res.ScopeId = splitPath[1]
	}

	// Walk backwards. As we walk backwards we look for a pin and figure out if
	// we're operating on a resource or a collection. The rules for the pin are
	// as follows:
	//
	// * If the last segment is a collection, the pin is the immediately
	// preceding ID. This does not include scopes since those are permission
	// boundaries.
	//
	// * If the last segment is an ID, the pin is the immediately preceding ID
	// not including the last segment
	//
	// * If at the end of the logic the pin is the id of a scope then there is
	// no pin. The scopes are already enclosing so a pin is redundant.
	nextIdIsPin := true
	// Use an empty string so we can detect if we found anything in this loop.
	var foundId string
	var typStr string
	// We stop at [2] because we've already dealt with the first two segments
	// (scopes/<scope_id> above.
	for i := splitLen - 1; i >= 2; i-- {
		segment := splitPath[i]

		if segment == "" {
			return fmt.Errorf("parse auth parameters: unexpected empty segment")
		}

		// Collections don't contain underscores; every resource ID does.
		segmentIsCollection := !strings.Contains(segment, "_")

		// If we see an ID, ensure that it's not the right-most ID; if not, it's
		// the pin
		if !segmentIsCollection && i != splitLen-1 && nextIdIsPin {
			v.res.Pin = segment
			// By definition this is the last thing we'd be looking for as
			// scopes were found above, so we can now break out
			break
		}

		if typStr == "" {
			// The resource check takes place inside the type check because if
			// we've identified the type we have either already identified the
			// right-most resource ID or we're operating on a collection, so
			// this prevents us from finding a different ID earlier in the path.
			// We still work backwards to identify a pin.
			if foundId == "" && !segmentIsCollection {
				foundId = segment
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

	if foundId != "" {
		v.res.Id = foundId
	}

	if typStr != "" {
		v.res.Type = resource.Map[typStr]
		if v.res.Type == resource.Unknown {
			return fmt.Errorf("parse auth params: unknown resource type %q", typStr)
		}
	} else {
		// If we found no other type information, we walked backwards all the
		// way to the scope boundary, so the type is scope
		v.res.Type = resource.Scope
	}

	// If we're operating on a collection (that is, the ID is blank) and it's a
	// GET, it's actually a list
	if v.res.Id == "" && v.act == action.Read {
		v.act = action.List
	}

	// If the pin ended up being a scope, nil it out
	if v.res.Pin != "" && v.res.Pin == v.res.ScopeId {
		v.res.Pin = ""
	}

	return nil
}

func (v verifier) performAuthCheck() (aclResults *perms.ACLResults, userId, scopeId string, retErr error) {
	// Ensure we return an error by default if we forget to set this somewhere
	retErr = errors.New("unknown")
	// Make the linter happy
	_ = retErr
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
