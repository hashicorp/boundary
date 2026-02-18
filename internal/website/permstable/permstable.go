// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	// Import the ratelimiter logic for the side effect of getting all service
	// handlers imported and their resources and actions registered.
	_ "github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
)

const permsFile = "internal/website/permstable/resource-table.mdx"

var (
	iamScopes    = []string{"Global", "Org"}
	infraScope   = []string{"Project"}
	tableHeaders = []string{
		"API endpoint",
		"Parameters into permissions engine",
		"Available actions / examples",
	}
)

type Page struct {
	Resources []*Resource
}

type Resource struct {
	Type      string
	Scopes    []string
	Endpoints []*Endpoint
}

type Endpoint struct {
	Path    string
	Params  map[string]string
	Actions []*Action
}

type Action struct {
	Name        string
	Description string
	Examples    []string
}

var page = &Page{
	Resources: make([]*Resource, 0, 12),
}

func main() {
	var orderedResources []resource.Type
	for _, res := range resource.Map {
		orderedResources = append(orderedResources, res)
	}
	slices.SortFunc(orderedResources, func(a, b resource.Type) int {
		return strings.Compare(a.String(), b.String())
	})

	for _, res := range orderedResources {
		switch res {
		case resource.Unknown, resource.All, resource.Controller:
			continue
		}
		info := resources[res]

		name := strings.Replace(res.String(), "-", " ", 1)
		singularName := name
		switch []rune(strings.ToLower(singularName))[0] {
		case 'a', 'e', 'i', 'o':
			// 'u' is not included since our only u word is 'user' which
			// should use an 'a'.
			singularName = "an " + singularName
		default:
			singularName = "a " + singularName
		}

		var pin string
		if parent := res.Parent(); parent != res {
			pin = parent.String()
		}
		collectionEndpoints := &Endpoint{
			Path: fmt.Sprintf("/%s", res.PluralString()),
			Params: map[string]string{
				"Type": res.String(),
			},
		}
		colActions, err := action.CollectionActionSetForResource(res)
		if err != nil {
			panic("This shouldn't happen!")
		}
		for a := range colActions {
			actionName := a.String()
			examples := []string{
				fmt.Sprintf("type=<type>;actions=%s", actionName),
			}
			if strings.Contains(actionName, ":") {
				parentActionName := strings.SplitN(actionName, ":", 1)[0]
				examples = append([]string{fmt.Sprintf("type=<type>;actions=%s", parentActionName)}, examples...)
			}
			collectionEndpoints.Actions = append(collectionEndpoints.Actions, &Action{
				Name:        a.String(),
				Examples:    examples,
				Description: info.description(a, singularName),
			})
		}
		slices.SortFunc(collectionEndpoints.Actions, func(a, b *Action) int {
			return strings.Compare(a.Name, b.Name)
		})

		idEndpoints := &Endpoint{
			Path: fmt.Sprintf("/%s/<id>", res.PluralString()),
			Params: map[string]string{
				"ID":   "<id>",
				"Type": res.String(),
			},
		}
		if pin != "" {
			idEndpoints.Params["Pin"] = fmt.Sprintf("<%s-id>", pin)
		}
		idActionSet, err := action.IdActionSetForResource(res)
		if err != nil {
			panic("This shouldn't happen!")
		}
		var idActions []action.Type
		for a := range idActionSet {
			idActions = append(idActions, a)
		}

		// Always put the first actions as Read, Update, Delete in that order
		weighted := map[action.Type]int{
			action.Read:   100,
			action.Update: 90,
			action.Delete: 80,
		}
		slices.SortFunc(idActions, func(a, b action.Type) int {
			aWeight := weighted[a]
			bWeight := weighted[b]
			return strings.Compare(a.String(), b.String()) - aWeight + bWeight
		})

		for _, a := range idActions {
			if a == action.NoOp {
				continue
			}
			examples := []string{
				fmt.Sprintf("ids=<id>;actions=%s", a.String()),
			}
			if pin != "" {
				examples = append(examples, fmt.Sprintf("ids=<pin>;type=<type>;actions=%s", a.String()))
			}
			idEndpoints.Actions = append(idEndpoints.Actions, &Action{
				Name:        a.String(),
				Examples:    examples,
				Description: info.description(a, singularName),
			})
		}

		endpoints := make([]*Endpoint, 0, 2)
		if len(collectionEndpoints.Actions) > 0 {
			endpoints = append(endpoints, collectionEndpoints)
		}
		if len(idEndpoints.Actions) > 0 {
			endpoints = append(endpoints, idEndpoints)
		}
		pr := &Resource{
			Type:      name,
			Scopes:    info.scopes,
			Endpoints: endpoints,
		}

		page.Resources = append(page.Resources, pr)
	}

	fileContents, err := os.ReadFile(permsFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	lines := strings.Split(string(fileContents), "\n")
	var pre, post []string
	var marker int
	for i, line := range lines {
		if strings.Contains(line, "BEGIN TABLE") {
			marker = i
		}
		pre = append(pre, line)
		if marker != 0 {
			break
		}
	}

	for i := marker + 1; i < len(lines); i++ {
		if !strings.Contains(lines[i], "END TABLE") {
			continue
		}
		marker = i
		break
	}

	for i := marker; i < len(lines); i++ {
		post = append(post, lines[i])
	}

	final := fmt.Sprintf("%s\n\n%s\n\n%s\n\n%s",
		strings.Join(pre, "\n"),
		strings.Join(page.MarshalTableOfContents(), "\n"),
		strings.Join(page.MarshalBody(), "\n"),
		strings.Join(post, "\n"))

	if err := os.WriteFile(permsFile, []byte(final), 0o644); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func (p *Page) MarshalTableOfContents() (ret []string) {
	for _, v := range p.Resources {
		ret = append(ret, fmt.Sprintf(
			"- [%s](#%s)",
			toSentenceCase(v.Type),
			strings.ReplaceAll(strings.ToLower(v.Type), " ", "-"),
		))
	}

	return ret
}

func (p *Page) MarshalBody() (ret []string) {
	for _, v := range p.Resources {
		ret = append(ret, v.Marshal()...)
		ret = append(ret, "")
	}

	return ret
}

func (r *Resource) Marshal() (ret []string) {
	// Section Header
	ret = append(ret, fmt.Sprintf("## %s\n", toSentenceCase(r.Type)))

	// Scopes information
	var scopes []string
	for _, s := range r.Scopes {
		scopes = append(scopes, fmt.Sprintf("**%s**", s))
	}
	if len(scopes) > 0 {
		ret = append(ret, fmt.Sprintf(
			"The **%s** resource type supports the following scopes: %s\n",
			toSentenceCase(r.Type),
			strings.TrimSpace(strings.Join(scopes, ", ")),
		))
	}

	// Table Header
	ret = append(ret, fmt.Sprintf("| %s |", strings.Join(tableHeaders, " | ")))
	var headerSeparators []string
	for _, t := range tableHeaders {
		headerSeparators = append(headerSeparators, strings.Repeat("-", len(t)))
	}
	ret = append(ret, fmt.Sprintf("| %s |", strings.Join(headerSeparators, " | ")))

	// Table Body
	for _, v := range r.Endpoints {
		ret = append(ret, v.Marshal()...)
	}

	return ret
}

func (e *Endpoint) Marshal() (ret []string) {
	var row []string

	// Endpoint Field
	row = append(row, fmt.Sprintf("<code>%s</code>", escape(e.Path)))

	// Parameters Field
	pString := "<ul>"
	for _, v := range sortedKeys(e.Params) {
		pString = fmt.Sprintf("%s<li>%s</li>", pString, v)
		pString = fmt.Sprintf("%s<ul><li><code>%s</code></li></ul>", pString, escape(e.Params[v]))
	}
	pString = fmt.Sprintf("%s</ul>", pString)
	row = append(row, pString)

	// Actions Field
	aString := "<ul>"
	for _, v := range e.Actions {
		aString = fmt.Sprintf(
			"%s<li><code>%s</code>: %s</li>",
			aString,
			escape(v.Name),
			v.Description,
		)

		eString := "<ul>"
		for _, x := range v.Examples {
			// Intentionally using markdown code highlighting here for readability
			eString = fmt.Sprintf("%s<li>`%s`</li>", eString, x)
		}
		eString = fmt.Sprintf("%s</ul>", eString)

		aString = fmt.Sprintf("%s%s", aString, eString)
	}
	aString = fmt.Sprintf("%s</ul>", aString)
	row = append(row, aString)

	ret = append(ret, fmt.Sprintf("| %s |", strings.Join(row, " | ")))

	return ret
}

func toSentenceCase(s string) string {
	return fmt.Sprintf(
		"%s%s",
		strings.ToUpper(s[:1]), strings.ToLower(s[1:]),
	)
}

func escape(s string) string {
	ret := strings.Replace(s, "<", "&lt;", -1)
	return strings.Replace(ret, ">", "&gt;", -1)
}

func sortedKeys(in map[string]string) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// info holds information for a specific resource
type info struct {
	// The scopes this resource can be in
	scopes []string
	// If the auto generated descriptions do not correctly cover these actions
	// for this resource, including the action and a description here will
	// cause this to be used instead of the auto generated one.
	actionDescOverrides map[action.Type]string
}

// get the description for a resource.
func (i info) description(t action.Type, singleResourceName string) string {
	if s, ok := i.actionDescOverrides[t]; ok {
		return s
	}
	switch t {
	case action.List:
		singleResourceName := strings.TrimPrefix(strings.TrimPrefix(singleResourceName, "an "), "a ")
		return fmt.Sprintf("List %ss", singleResourceName)
	case action.Read:
		return fmt.Sprintf("Read %s", singleResourceName)
	case action.Update:
		return fmt.Sprintf("Update %s", singleResourceName)
	case action.Delete:
		return fmt.Sprintf("Delete %s", singleResourceName)
	case action.Create:
		return fmt.Sprintf("Create %s", singleResourceName)
	}
	switch {
	case strings.HasPrefix(t.String(), "add-"):
		thing := strings.SplitN(t.String(), "-", 2)[1]
		thing = strings.ReplaceAll(thing, "-", " ")
		return fmt.Sprintf("Add %s to %s", thing, singleResourceName)
	case strings.HasPrefix(t.String(), "set-"):
		thing := strings.SplitN(t.String(), "-", 2)[1]
		thing = strings.ReplaceAll(thing, "-", " ")
		return fmt.Sprintf("Set the full set of %s on %s", thing, singleResourceName)
	case strings.HasPrefix(t.String(), "remove-"):
		thing := strings.SplitN(t.String(), "-", 2)[1]
		thing = strings.ReplaceAll(thing, "-", " ")
		return fmt.Sprintf("Remove %s from %s", thing, singleResourceName)
	}
	return ""
}

var resources = map[resource.Type]info{
	resource.Account: {
		scopes: iamScopes,
		actionDescOverrides: map[action.Type]string{
			action.SetPassword:    "Set a password on an account, without requiring the current password",
			action.ChangePassword: "Change a password on an account given the current password",
		},
	},
	resource.Alias: {
		scopes: []string{"Global"},
		actionDescOverrides: map[action.Type]string{
			action.List: "List aliases",
		},
	},
	resource.AuthMethod: {
		scopes: iamScopes,
		actionDescOverrides: map[action.Type]string{
			action.Authenticate: "Authenticate to an auth method",
			action.ChangeState: "Change the active and visibility state of an OIDC-type auth method",
		},
	},
	resource.AuthToken: {
		scopes: iamScopes,
		actionDescOverrides: map[action.Type]string{
			action.DeleteSelf: "Deletes the auth token associated with the current user",
			action.ReadSelf: "Reads the details of the auth token associated with the current user",
		},
	},
	resource.Billing: {
		scopes: []string{"Global"},
		actionDescOverrides: map[action.Type]string{
			action.MonthlyActiveUsers: "Display the number of monthly active Boundary users to help predict billing",
		},
	},
	resource.Credential: {
		scopes: infraScope,
	},
	resource.CredentialLibrary: {
		scopes: infraScope,
		actionDescOverrides: map[action.Type]string{
			action.List: "List credential libraries",
		},
	},
	resource.CredentialStore: {
		scopes: infraScope,
	},
	resource.Group: {
		scopes: append(iamScopes, infraScope...),
	},
	resource.Host: {
		scopes: infraScope,
	},
	resource.HostCatalog: {
		scopes: infraScope,
	},
	resource.HostSet: {
		scopes: infraScope,
	},
	resource.ManagedGroup: {
		scopes: iamScopes,
	},
	resource.Policy: {
		scopes: iamScopes,
		actionDescOverrides: map[action.Type]string{
			action.List: "List policies",
		},
	},
	resource.Role: {
		scopes: append(iamScopes, infraScope...),
	},
	resource.Scope: {
		scopes: iamScopes,
		actionDescOverrides: map[action.Type]string{
			action.DestroyScopeKeyVersion: "Destroy a key version in the scope",
			action.ListScopeKeyVersionDestructionJobs: "List all pending key version destruction jobs within a scope",
			action.ListScopeKeys: "List the keys within a given scope",
			action.RotateScopeKeys: "Replace a scope's current KEK and DEKs with a new set of keys",
			action.AttachStoragePolicy: "Attach a storage policy to all session recordings in the scope",
			action.DetachStoragePolicy: "Detach a storage policy from all session recordings in the scope",
		},
	},
	resource.Session: {
		scopes: infraScope,
		actionDescOverrides: map[action.Type]string{
			action.Cancel:     "Cancel a session",
			action.CancelSelf: "Cancel a session, which must be associated with the calling user",
			action.ReadSelf:   "Read a session, which must be associated with the calling user",
		},
	},
	resource.SessionRecording: {
		scopes: iamScopes,
		actionDescOverrides: map[action.Type]string{
			action.Download:             "Download a session recording",
			action.ReApplyStoragePolicy: "Reapply the storage policy to a session recording",
		},
	},
	resource.StorageBucket: {
		scopes: iamScopes,
	},
	resource.Target: {
		scopes: infraScope,
		actionDescOverrides: map[action.Type]string{
			action.AuthorizeSession: "Authorize a session via the target",
		},
	},
	resource.User: {
		scopes: iamScopes,
		actionDescOverrides: map[action.Type]string{
			action.ListResolvableAliases: "List all aliases that point to resources the user has permission to access",
		},
	},
	resource.Worker: {
		scopes: []string{"Global"},
		actionDescOverrides: map[action.Type]string{
			action.CreateControllerLed: "Create a worker using the controller-led workflow",
			action.CreateWorkerLed:     "Create a worker using the worker-led workflow",
			action.ReadCertificateAuthority: "Read the details of the certificate authority that is used to authorize Boundary workers",
			action.ReinitializeCertificateAuthority: "Reinitialize the certificate authority that is used to authorize Boundary workers",
		},
	},
}
