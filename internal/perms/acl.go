package perms

/*
A really useful page to be aware of when looking at ACLs is
https://hashicorp.atlassian.net/wiki/spaces/ICU/pages/866976600/API+Actions+and+Permissions
speaking of which: TODO: put that chart in public docs.

Anyways, from that page you can see that there are really only a few patterns of
ACLs that are ever allowed:

* type=<resource.type>;actions=<action>
* id=<resource.id>;actions=<action>
* id=<pin>;type=<resource.type>;actions=<action>

and of course a matching scope.

This makes it actually quite simple to perform the ACL checking. Much of ACL
construction is thus synthesizing something reasonable from a set of Grants.
*/

import "github.com/hashicorp/watchtower/internal/iam"

type ACL struct {
	scopeMap map[string][]Grant
}

// This is a struct so that we can pass more detailed information along in the
// future if we want. It was useful in Vault, may be useful here.
type ACLResults struct {
	Allowed bool
}

type Resource struct {
	ScopeId string
	Id      string
	Type    string
	Pin     string
}

func NewACL(grants ...Grant) ACL {
	ret := ACL{
		scopeMap: make(map[string][]Grant, len(grants)),
	}

	for _, grant := range grants {
		ret.scopeMap[grant.Scope.Id] = append(ret.scopeMap[grant.Scope.Id], grant)
	}

	return ret
}

func (a ACL) Allowed(resource Resource, action iam.Action) (results ACLResults) {
	// First, get the grants within the specified scope
	grants := a.scopeMap[resource.ScopeId]

	// Now, go through and check the cases indicated above
	for _, grant := range grants {
		if !(grant.Actions[action] || grant.Actions[iam.ActionAll]) {
			continue
		}
		switch {
		// type=<resource.type>;actions=<action>
		case grant.Id == "" &&
			grant.Type == resource.Type:
			results.Allowed = true
			return

		// id=<resource.id>;actions=<action>
		case grant.Id == resource.Id &&
			grant.Type == "":
			results.Allowed = true
			return

		// id=<pin>;type=<resource.type>;actions=<action>
		case grant.Id == resource.Pin &&
			grant.Type == resource.Type:
			results.Allowed = true
			return
		}
	}
	return
}
