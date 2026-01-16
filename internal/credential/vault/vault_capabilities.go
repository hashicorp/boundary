// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"sort"
	"strings"
)

type capabilities uint

const noCapabilities = capabilities(0)

const (
	denyCapability capabilities = 1 << iota
	createCapability
	readCapability
	updateCapability
	deleteCapability
	listCapability
	sudoCapability
	rootCapability
)

var string2Cap = map[string]capabilities{
	"deny":   denyCapability,
	"create": createCapability,
	"read":   readCapability,
	"update": updateCapability,
	"delete": deleteCapability,
	"list":   listCapability,
	"sudo":   sudoCapability,
	"root":   rootCapability,
}

func (c capabilities) goStrings() []string {
	if c == noCapabilities {
		return nil
	}

	var caps []string
	if c&denyCapability == denyCapability {
		caps = append(caps, "denyCapability")
	}
	if c&createCapability == createCapability {
		caps = append(caps, "createCapability")
	}
	if c&readCapability == readCapability {
		caps = append(caps, "readCapability")
	}
	if c&updateCapability == updateCapability {
		caps = append(caps, "updateCapability")
	}
	if c&deleteCapability == deleteCapability {
		caps = append(caps, "deleteCapability")
	}
	if c&listCapability == listCapability {
		caps = append(caps, "listCapability")
	}
	if c&sudoCapability == sudoCapability {
		caps = append(caps, "sudoCapability")
	}
	if c&rootCapability == rootCapability {
		caps = append(caps, "rootCapability")
	}
	return caps
}

func (c capabilities) GoString() string {
	if c == noCapabilities {
		return "vault.capabilities{}"
	}
	caps := c.goStrings()
	var b strings.Builder
	b.WriteString("vault.capabilities{ ")
	b.WriteString(strings.Join(caps, " | "))
	b.WriteString(" }")
	return b.String()
}

func (c capabilities) strings() []string {
	if c == noCapabilities {
		return nil
	}

	var caps []string
	if c&denyCapability == denyCapability {
		caps = append(caps, "deny")
	}
	if c&createCapability == createCapability {
		caps = append(caps, "create")
	}
	if c&readCapability == readCapability {
		caps = append(caps, "read")
	}
	if c&updateCapability == updateCapability {
		caps = append(caps, "update")
	}
	if c&deleteCapability == deleteCapability {
		caps = append(caps, "delete")
	}
	if c&listCapability == listCapability {
		caps = append(caps, "list")
	}
	if c&sudoCapability == sudoCapability {
		caps = append(caps, "sudo")
	}
	if c&rootCapability == rootCapability {
		caps = append(caps, "root")
	}

	return caps
}

func (c capabilities) String() string {
	if c == noCapabilities {
		return "[]"
	}
	caps := c.strings()
	var b strings.Builder
	b.WriteString(`["`)
	b.WriteString(strings.Join(caps, `", "`))
	b.WriteString(`"]`)
	return b.String()
}

func (c capabilities) hasDeny() bool {
	return c&denyCapability == denyCapability
}

func (c capabilities) missing(required capabilities) capabilities {
	return required &^ c
}

type pathCapabilities map[string]capabilities

func newPathCapabilities(results map[string][]string) pathCapabilities {
	pc := make(pathCapabilities, len(results))
	for path, caps := range results {
		for _, cap := range caps {
			pc[path] |= string2Cap[cap]
		}
	}
	return pc
}

// has reports if the path has all of the required capabilities.
// has always returns false if deny has been set on the path.
// deny is ignored if it is included in the list of required capabilities.
func (pc pathCapabilities) has(path string, required ...capabilities) bool {
	if pc[path].hasDeny() {
		return false
	}
	var allRequiredCaps capabilities
	for _, cap := range required {
		allRequiredCaps |= cap
	}
	// deny cannot be in the required list
	allRequiredCaps &^= denyCapability
	return pc[path]&allRequiredCaps != 0
}

// get returns the capabilities for path and a boolean to indicate if the
// path was set.
func (pc pathCapabilities) get(path string) (capabilities, bool) {
	c, ok := pc[path]
	return c, ok
}

// union creates and returns a new pathCapabilities instance, z. union sets
// z[p] = x[p] | y[p] for all p, where p is a path from the set of paths
// from x and y.
func (pc pathCapabilities) union(y pathCapabilities) (z pathCapabilities) {
	if len(pc) == 0 && len(y) == 0 {
		return z
	}
	max := func(a, b int) int {
		if a < b {
			return a
		}
		return b
	}
	z = make(pathCapabilities, max(len(pc), len(y)))
	for p := range pc {
		z[p] = pc[p] | y[p]
	}
	for p := range y {
		z[p] = pc[p] | y[p]
	}
	return z
}

func (pc pathCapabilities) missing(required pathCapabilities) pathCapabilities {
	switch {
	case len(required) == 0:
		return nil
	case len(pc) == 0:
		z := make(pathCapabilities, len(required))
		for p := range required {
			z[p] = required[p]
		}
		return z
	}

	var z pathCapabilities
	for p, c := range required {
		mc := pc[p].missing(c)
		if mc != noCapabilities {
			if z == nil {
				z = make(pathCapabilities)
			}
			z[p] = mc
		}
	}
	return z
}

func (pc pathCapabilities) vaultPolicy() string {
	if len(pc) == 0 {
		return ""
	}

	var paths []string
	for path := range pc {
		if pc[path] != noCapabilities {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		return ""
	}

	sort.Strings(paths)
	var sep string
	b := new(strings.Builder)
	for _, path := range paths {
		b.WriteString(sep)
		fmt.Fprintf(b, "path %q {\n", path)
		fmt.Fprintf(b, "\tcapabilities = %s\n", pc[path])
		b.WriteString("}\n")
		sep = "\n"
	}
	return b.String()
}

func (pc pathCapabilities) paths() []string {
	var paths []string
	for path := range pc {
		paths = append(paths, path)
	}
	return paths
}

func (pc pathCapabilities) String() string {
	var b strings.Builder
	for k, v := range pc {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(strings.Join(v.strings(), "|"))
		b.WriteString(", ")
	}
	return strings.TrimSuffix(b.String(), ", ")
}

var requiredCapabilities = pathCapabilities{
	"auth/token/lookup-self": readCapability,
	"auth/token/renew-self":  updateCapability,
	"auth/token/revoke-self": updateCapability,
	"sys/leases/renew":       updateCapability,
	"sys/leases/revoke":      updateCapability,
}
