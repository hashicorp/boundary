package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
)

const permsFile = "website/content/docs/concepts/permissions.mdx"

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
	table.Body.Resources = append(table.Body.Resources, authMethod)

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

	if err := ioutil.WriteFile(permsFile, []byte(final), 0644); err != nil {
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
				fmt.Sprintf(`%s<td rowspan="%d">%s</td>`, indent(6), len(r.Endpoints), r.Type),
				fmt.Sprintf(`%s<td rowspan="%d">`, indent(6), len(r.Endpoints)),
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
			fmt.Sprintf(`%s<ul>`, indent(12)),
			fmt.Sprintf(`%s<li>`, indent(14)),
			fmt.Sprintf(`%s<code>%s</code>`, indent(16), escape(e.Params[v])),
			fmt.Sprintf(`%s</li>`, indent(14)),
			fmt.Sprintf(`%s</ul>`, indent(12)),
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
			fmt.Sprintf(`%s<ul>`, indent(12)),
		)
		for _, x := range v.Examples {
			ret = append(ret,
				fmt.Sprintf(`%s<li><code>%s</code></li>`, indent(14), escape(x)),
			)
		}
		ret = append(ret,
			fmt.Sprintf(`%s</ul>`, indent(12)),
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

func clActions(typ string) []*Action {
	return []*Action{
		{
			Name:        "create",
			Description: fmt.Sprintf("Create %s", typ),
			Examples: []string{
				"type=<resource.type>;actions=create",
				"type=*;actions=create",
			},
		},
		{
			Name:        "list",
			Description: fmt.Sprintf("List %ss", strings.TrimPrefix(strings.TrimPrefix(typ, "an "), "a ")),
			Examples: []string{
				"type=<resource.type>;actions=list",
				"type=*;actions=list",
			},
		},
	}
}

func rudActions(typ string) []*Action {
	return []*Action{
		{
			Name:        "read",
			Description: fmt.Sprintf("Read %s", typ),
			Examples: []string{
				"id=<resource.id>;actions=read",
				"id=*;type=<resource.type>;actions=read",
			},
		},
		{
			Name:        "update",
			Description: fmt.Sprintf("Update %s", typ),
			Examples: []string{
				"id=<resource.id>;actions=update",
				"id=*;type=<resource.type>;actions=update",
			},
		},
		{
			Name:        "delete",
			Description: fmt.Sprintf("Delete %s", typ),
			Examples: []string{
				"id=<resource.id>;actions=delete",
				"id=*;type=<resource.type>;actions=delete",
			},
		},
	}
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
			Actions: rudActions("an auth method"),
		},
	},
}
