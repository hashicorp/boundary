// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
)

const permsFile = "website/content/docs/concepts/security/permissions/resource-table.mdx"

var (
	iamScopes  = []string{"Global", "Org"}
	infraScope = []string{"Project"}
)

type Table struct {
	Header *Header
	Body   *Body
}

type Header struct {
	Titles []string
}

type Body struct {
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

var table = &Table{
	Header: &Header{
		Titles: []string{
			"Resource Type",
			"Applicable Scopes",
			"API Endpoint",
			"Parameters into Permissions Engine",
			"Available Actions / Examples",
		},
	},
	Body: &Body{
		Resources: make([]*Resource, 0, 12),
	},
}

func main() {
	table.Body.Resources = append(table.Body.Resources,
		account,
		authMethod,
		authToken,
		group,
		host,
		hostCatalog,
		hostSet,
		managedGroup,
		role,
		scope,
		session,
		sessionRecording,
		storageBucket,
		target,
		user,
		worker,
	)

	fileContents, err := ioutil.ReadFile(permsFile)
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

	final := fmt.Sprintf("%s\n\n%s\n\n%s",
		strings.Join(pre, "\n"),
		strings.Join(table.Marshal(), "\n"),
		strings.Join(post, "\n"))

	if err := ioutil.WriteFile(permsFile, []byte(final), 0o644); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func (t *Table) Marshal() (ret []string) {
	ret = append(ret, "<table>")
	ret = append(ret, "  <thead>")
	ret = append(ret, t.Header.Marshal()...)
	ret = append(ret, "  </thead>")
	ret = append(ret, "  <tbody>")
	ret = append(ret, t.Body.Marshal()...)
	ret = append(ret, "  </tbody>")
	ret = append(ret, "</table>")

	return
}

func (h *Header) Marshal() (ret []string) {
	ret = append(ret, fmt.Sprintf(`%s<tr>`, indent(4)))
	for _, v := range h.Titles {
		ret = append(ret,
			fmt.Sprintf("%s<th>%s</th>", indent(6), v),
		)
	}
	ret = append(ret, fmt.Sprintf(`%s</tr>`, indent(4)))

	return
}

func (b *Body) Marshal() (ret []string) {
	for _, v := range b.Resources {
		ret = append(ret, v.Marshal()...)
	}

	return
}

func (r *Resource) Marshal() (ret []string) {
	for i, v := range r.Endpoints {
		ret = append(ret, fmt.Sprintf(`%s<tr>`, indent(4)))
		if i == 0 {
			ret = append(ret,
				fmt.Sprintf(`%s<td rowSpan="%d">%s</td>`, indent(6), len(r.Endpoints), r.Type),
				fmt.Sprintf(`%s<td rowSpan="%d">`, indent(6), len(r.Endpoints)),
				fmt.Sprintf(`%s<ul>`, indent(8)),
			)
			for _, s := range r.Scopes {
				ret = append(ret,
					fmt.Sprintf(`%s<li>%s</li>`, indent(10), s),
				)
			}
			ret = append(ret,
				fmt.Sprintf(`%s</ul>`, indent(8)),
				fmt.Sprintf(`%s</td>`, indent(6)),
			)
		}
		ret = append(ret, v.Marshal()...)
		ret = append(ret, fmt.Sprintf(`%s</tr>`, indent(4)))
	}

	return
}

func (e *Endpoint) Marshal() (ret []string) {
	ret = append(ret,
		fmt.Sprintf(`%s<td>`, indent(6)),
		fmt.Sprintf(`%s<code>%s</code>`, indent(8), escape(e.Path)),
		fmt.Sprintf(`%s</td>`, indent(6)),
		fmt.Sprintf(`%s<td>`, indent(6)),
		fmt.Sprintf(`%s<ul>`, indent(8)),
	)

	for _, v := range sortedKeys(e.Params) {
		ret = append(ret,
			fmt.Sprintf(`%s<li>%s</li>`, indent(10), v),
			fmt.Sprintf(`%s<ul>`, indent(10)),
			fmt.Sprintf(`%s<li>`, indent(12)),
			fmt.Sprintf(`%s<code>%s</code>`, indent(14), escape(e.Params[v])),
			fmt.Sprintf(`%s</li>`, indent(12)),
			fmt.Sprintf(`%s</ul>`, indent(10)),
		)
	}

	ret = append(ret,
		fmt.Sprintf(`%s</ul>`, indent(8)),
		fmt.Sprintf(`%s</td>`, indent(6)),
		fmt.Sprintf(`%s<td>`, indent(6)),
		fmt.Sprintf(`%s<ul>`, indent(8)),
	)

	for _, v := range e.Actions {
		ret = append(ret,
			fmt.Sprintf(`%s<li>`, indent(10)),
			fmt.Sprintf(`%s<code>%s</code>: %s`, indent(12), v.Name, v.Description),
			fmt.Sprintf(`%s</li>`, indent(10)),
		)
		ret = append(ret,
			fmt.Sprintf(`%s<ul>`, indent(10)),
		)
		for _, x := range v.Examples {
			ret = append(ret,
				fmt.Sprintf(`%s<li>`, indent(12)),
				fmt.Sprintf(`%s<code>%s</code>`, indent(14), escape(x)),
				fmt.Sprintf(`%s</li>`, indent(12)),
			)
		}
		ret = append(ret,
			fmt.Sprintf(`%s</ul>`, indent(10)),
		)
	}

	ret = append(ret,
		fmt.Sprintf(`%s</ul>`, indent(8)),
		fmt.Sprintf(`%s</td>`, indent(6)),
	)

	return
}

func escape(s string) string {
	ret := strings.Replace(s, "<", "&lt;", -1)
	return strings.Replace(ret, ">", "&gt;", -1)
}

func indent(num int) string {
	return strings.Repeat(" ", num)
}

func sortedKeys(in map[string]string) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func lActions(typ string) []*Action {
	listVersion := strings.TrimPrefix(strings.TrimPrefix(typ, "an "), "a ")
	return []*Action{
		{
			Name:        "list",
			Description: fmt.Sprintf("List %ss", listVersion),
			Examples: []string{
				"type=<type>;actions=list",
			},
		},
	}
}

func clActions(typ string) []*Action {
	return append([]*Action{
		{
			Name:        "create",
			Description: fmt.Sprintf("Create %s", typ),
			Examples: []string{
				"type=<type>;actions=create",
			},
		},
	}, lActions(typ)...)
}

func rudActions(typ string, pin bool) []*Action {
	ret := []*Action{
		{
			Name:        "read",
			Description: fmt.Sprintf("Read %s", typ),
			Examples: []string{
				"id=<id>;actions=read",
			},
		},
		{
			Name:        "update",
			Description: fmt.Sprintf("Update %s", typ),
			Examples: []string{
				"id=<id>;actions=update",
			},
		},
		{
			Name:        "delete",
			Description: fmt.Sprintf("Delete %s", typ),
			Examples: []string{
				"id=<id>;actions=delete",
			},
		},
	}
	if pin {
		ret[0].Examples = append(ret[0].Examples, "id=<pin>;type=<type>;actions=read")
		ret[1].Examples = append(ret[1].Examples, "id=<pin>;type=<type>;actions=update")
		ret[2].Examples = append(ret[2].Examples, "id=<pin>;type=<type>;actions=delete")
	}

	return ret
}

var account = &Resource{
	Type:   "Account",
	Scopes: iamScopes,
	Endpoints: []*Endpoint{
		{
			Path: "/accounts",
			Params: map[string]string{
				"Type": "account",
			},
			Actions: clActions("an account"),
		},
		{
			Path: "/accounts/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "account",
				"Pin":  "<auth-method-id>",
			},
			Actions: append(
				rudActions("an account", true),
				&Action{
					Name:        "set-password",
					Description: "Set a password on an account, without requiring the current password",
					Examples: []string{
						"id=<id>;actions=set-password",
						"id=<pin>;type=<type>;actions=set-password",
					},
				},
				&Action{
					Name:        "change-password",
					Description: "Change a password on an account given the current password",
					Examples: []string{
						"id=<id>;actions=change-password",
						"id=<pin>;type=<type>;actions=change-password",
					},
				},
			),
		},
	},
}

var authMethod = &Resource{
	Type:   "Auth Method",
	Scopes: iamScopes,
	Endpoints: []*Endpoint{
		{
			Path: "/auth-methods",
			Params: map[string]string{
				"Type": "auth-method",
			},
			Actions: clActions("an auth method"),
		},
		{
			Path: "/auth-methods/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "auth-method",
			},
			Actions: append(
				rudActions("an auth method", false),
				&Action{
					Name:        "authenticate",
					Description: "Authenticate to an auth method",
					Examples: []string{
						"id=<id>;actions=authenticate",
					},
				},
			),
		},
	},
}

var authToken = &Resource{
	Type:   "Auth Token",
	Scopes: iamScopes,
	Endpoints: []*Endpoint{
		{
			Path: "/auth-tokens",
			Params: map[string]string{
				"Type": "auth-token",
			},
			Actions: []*Action{
				{
					Name:        "list",
					Description: "List auth tokens",
					Examples: []string{
						"type=<type>;actions=list",
					},
				},
			},
		},
		{
			Path: "/auth-tokens/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "auth-token",
			},
			Actions: []*Action{
				{
					Name:        "read",
					Description: "Read an auth token",
					Examples: []string{
						"id=<id>;actions=read",
					},
				},
				{
					Name:        "delete",
					Description: "Delete an auth token",
					Examples: []string{
						"id=<id>;actions=delete",
					},
				},
			},
		},
	},
}

var group = &Resource{
	Type:   "Group",
	Scopes: append(iamScopes, infraScope...),
	Endpoints: []*Endpoint{
		{
			Path: "/groups",
			Params: map[string]string{
				"Type": "group",
			},
			Actions: clActions("a group"),
		},
		{
			Path: "/groups/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "group",
			},
			Actions: append(
				rudActions("a group", false),
				&Action{
					Name:        "add-members",
					Description: "Add members to a group",
					Examples: []string{
						"id=<id>;actions=add-members",
					},
				},
				&Action{
					Name:        "set-members",
					Description: "Set the full set of members on a group",
					Examples: []string{
						"id=<id>;actions=set-members",
					},
				},
				&Action{
					Name:        "remove-members",
					Description: "Remove members from a group",
					Examples: []string{
						"id=<id>;actions=remove-members",
					},
				},
			),
		},
	},
}

var host = &Resource{
	Type:   "Host",
	Scopes: infraScope,
	Endpoints: []*Endpoint{
		{
			Path: "/hosts",
			Params: map[string]string{
				"Type": "host",
			},
			Actions: clActions("a host"),
		},
		{
			Path: "/hosts/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "host",
				"Pin":  "<host-catalog-id>",
			},
			Actions: rudActions("a host", true),
		},
	},
}

var hostCatalog = &Resource{
	Type:   "Host Catalog",
	Scopes: infraScope,
	Endpoints: []*Endpoint{
		{
			Path: "/host-catalogs",
			Params: map[string]string{
				"Type": "host-catalog",
			},
			Actions: clActions("a host catalog"),
		},
		{
			Path: "/host-catalogs/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "host-catalog",
			},
			Actions: rudActions("a host catalog", false),
		},
	},
}

var hostSet = &Resource{
	Type:   "Host Set",
	Scopes: infraScope,
	Endpoints: []*Endpoint{
		{
			Path: "/host-sets",
			Params: map[string]string{
				"Type": "host-set",
			},
			Actions: clActions("a host set"),
		},
		{
			Path: "/host-sets/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "host-set",
				"Pin":  "<host-catalog-id>",
			},
			Actions: append(
				rudActions("a host set", true),
				&Action{
					Name:        "add-hosts",
					Description: "Add hosts to a host-set",
					Examples: []string{
						"id=<id>;actions=add-hosts",
						"id=<pin>;type=<type>;actions=add-hosts",
					},
				},
				&Action{
					Name:        "set-hosts",
					Description: "Set the full set of hosts on a host set",
					Examples: []string{
						"id=<id>;actions=set-hosts",
						"id=<pin>;type=<type>;actions=set-hosts",
					},
				},
				&Action{
					Name:        "remove-hosts",
					Description: "Remove hosts from a host set",
					Examples: []string{
						"id=<id>;actions=remove-hosts",
						"id=<pin>;type=<type>;actions=remove-hosts",
					},
				},
			),
		},
	},
}

var managedGroup = &Resource{
	Type:   "Managed Group",
	Scopes: iamScopes,
	Endpoints: []*Endpoint{
		{
			Path: "/managed-groups",
			Params: map[string]string{
				"Type": "managed-group",
			},
			Actions: clActions("a managed group"),
		},
		{
			Path: "/managed-groups/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "managed-group",
				"Pin":  "<auth-method-id>",
			},
			Actions: rudActions("a managed group", true),
		},
	},
}

var role = &Resource{
	Type:   "Role",
	Scopes: append(iamScopes, infraScope...),
	Endpoints: []*Endpoint{
		{
			Path: "/roles",
			Params: map[string]string{
				"Type": "role",
			},
			Actions: clActions("a role"),
		},
		{
			Path: "/roles/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "role",
			},
			Actions: append(
				rudActions("a role", false),
				&Action{
					Name:        "add-principals",
					Description: "Add principals to a role",
					Examples: []string{
						"id=<id>;actions=add-principals",
					},
				},
				&Action{
					Name:        "set-principals",
					Description: "Set the full set of principals on a role",
					Examples: []string{
						"id=<id>;actions=set-principals",
					},
				},
				&Action{
					Name:        "remove-principals",
					Description: "Remove principals from a role",
					Examples: []string{
						"id=<id>;actions=remove-principals",
					},
				},
				&Action{
					Name:        "add-grants",
					Description: "Add grants to a role",
					Examples: []string{
						"id=<id>;actions=add-grants",
					},
				},
				&Action{
					Name:        "set-grants",
					Description: "Set the full set of grants on a role",
					Examples: []string{
						"id=<id>;actions=set-grants",
					},
				},
				&Action{
					Name:        "remove-grants",
					Description: "Remove grants from a role",
					Examples: []string{
						"id=<id>;actions=remove-grants",
					},
				},
			),
		},
	},
}

var scope = &Resource{
	Type:   "Scope",
	Scopes: iamScopes,
	Endpoints: []*Endpoint{
		{
			Path: "/scopes",
			Params: map[string]string{
				"Type": "scope",
			},
			Actions: clActions("a scope"),
		},
		{
			Path: "/scopes/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "scope",
			},
			Actions: rudActions("a scope", false),
		},
	},
}

var session = &Resource{
	Type:   "Session",
	Scopes: infraScope,
	Endpoints: []*Endpoint{
		{
			Path: "/sessions",
			Params: map[string]string{
				"Type": "session",
			},
			Actions: []*Action{
				{
					Name:        "list",
					Description: "List sessions",
					Examples: []string{
						"type=<type>;actions=list",
					},
				},
			},
		},
		{
			Path: "/session/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "session",
			},
			Actions: []*Action{
				{
					Name:        "read",
					Description: "Read a session",
					Examples: []string{
						"id=<id>;actions=read",
					},
				},
				{
					Name:        "cancel",
					Description: "Cancel a session",
					Examples: []string{
						"id=<id>;actions=cancel",
					},
				},
				{
					Name:        "read:self",
					Description: "Read a session, which must be associated with the calling user",
					Examples: []string{
						"id=*;type=session;actions=read:self",
					},
				},
				{
					Name:        "cancel:self",
					Description: "Cancel a session, which must be associated with the calling user",
					Examples: []string{
						"id=*;type=session;actions=cancel:self",
					},
				},
			},
		},
	},
}

var sessionRecording = &Resource{
	Type:   "Session Recording",
	Scopes: iamScopes,
	Endpoints: []*Endpoint{
		{
			Path: "/session-recordings",
			Params: map[string]string{
				"Type": "session-recording",
			},
			Actions: []*Action{
				{
					Name:        "list",
					Description: "List session recordings",
					Examples: []string{
						"type=<type>;actions=list",
					},
				},
			},
		},
		{
			Path: "/session-recordings/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "session-recording",
			},
			Actions: []*Action{
				{
					Name:        "read",
					Description: "Read a session recording",
					Examples: []string{
						"id=<id>;actions=read",
					},
				},
				{
					Name:        "download",
					Description: "Download a session recording",
					Examples: []string{
						"id=<id>;actions=download",
					},
				},
			},
		},
	},
}

var storageBucket = &Resource{
	Type:   "Storage Bucket",
	Scopes: iamScopes,
	Endpoints: []*Endpoint{
		{
			Path: "/storage-buckets",
			Params: map[string]string{
				"Type": "storage-bucket",
			},
			Actions: clActions("a storage bucket"),
		},
		{
			Path: "/storage-buckets/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "storage-bucket",
			},
			Actions: rudActions("a storage bucket", false),
		},
	},
}

var target = &Resource{
	Type:   "Target",
	Scopes: infraScope,
	Endpoints: []*Endpoint{
		{
			Path: "/targets",
			Params: map[string]string{
				"Type": "target",
			},
			Actions: clActions("a target"),
		},
		{
			Path: "/targets/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "target",
			},
			Actions: append(
				rudActions("a target", false),
				&Action{
					Name:        "add-host-sources",
					Description: "Add host sources to a target",
					Examples: []string{
						"id=<id>;actions=add-host-sources",
					},
				},
				&Action{
					Name:        "set-host-sources",
					Description: "Set the full set of host sources on a target",
					Examples: []string{
						"id=<id>;actions=set-host-sources",
					},
				},
				&Action{
					Name:        "remove-host-sources",
					Description: "Remove host sources from a target",
					Examples: []string{
						"id=<id>;actions=remove-host-sources",
					},
				},
				&Action{
					Name:        "add-credential-sources",
					Description: "Add credential sources to a target",
					Examples: []string{
						"id=<id>;actions=add-credential-sources",
					},
				},
				&Action{
					Name:        "set-credential-sources",
					Description: "Set the full set of credential sources on a target",
					Examples: []string{
						"id=<id>;actions=set-credential-sources",
					},
				},
				&Action{
					Name:        "remove-credential-sources",
					Description: "Remove credential sources from a target",
					Examples: []string{
						"id=<id>;actions=remove-credential-sources",
					},
				},
				&Action{
					Name:        "authorize-session",
					Description: "Authorize a session via the target",
					Examples: []string{
						"id=<id>;actions=authorize-session",
					},
				},
			),
		},
	},
}

var user = &Resource{
	Type:   "User",
	Scopes: iamScopes,
	Endpoints: []*Endpoint{
		{
			Path: "/users",
			Params: map[string]string{
				"Type": "user",
			},
			Actions: clActions("a user"),
		},
		{
			Path: "/users/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "user",
			},
			Actions: append(
				rudActions("a user", false),
				&Action{
					Name:        "add-accounts",
					Description: "Add accounts to a user",
					Examples: []string{
						"id=<id>;actions=add-accounts",
					},
				},
				&Action{
					Name:        "set-accounts",
					Description: "Set the full set of accounts on a user",
					Examples: []string{
						"id=<id>;actions=set-accounts",
					},
				},
				&Action{
					Name:        "remove-accounts",
					Description: "Remove accounts from a user",
					Examples: []string{
						"id=<id>;actions=remove-accounts",
					},
				},
			),
		},
	},
}

var worker = &Resource{
	Type:   "Worker",
	Scopes: []string{"Global"},
	Endpoints: []*Endpoint{
		{
			Path: "/workers",
			Params: map[string]string{
				"Type": "worker",
			},
			Actions: append(
				lActions("a worker"),
				&Action{
					Name:        "create:controller-led",
					Description: "Create a worker using the controller-led workflow",
					Examples: []string{
						"type=<type>;actions=create",
						"type=<type>;actions=create:controller-led",
					},
				},
				&Action{
					Name:        "create:worker-led",
					Description: "Create a worker using the worker-led workflow",
					Examples: []string{
						"type=<type>;actions=create",
						"type=<type>;actions=create:worker-led",
					},
				},
			),
		},
		{
			Path: "/workers/<id>",
			Params: map[string]string{
				"ID":   "<id>",
				"Type": "worker",
			},
			Actions: append(
				rudActions("a worker", false),
			),
		},
	},
}
