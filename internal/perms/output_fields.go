// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package perms

import (
	"sort"

	"github.com/hashicorp/boundary/globals"
)

// OutputFields is used to store information about allowed output fields in
// grants
type OutputFields struct {
	fields map[string]bool
}

// AddFields adds the given fields and returns the interface. It is safe to call
// this on a nil object, which will create a new object and add the fields to
// it; if relying on this make sure to assign to the output, e.g.:
//
//	outFields = outFields.AddFields([]string{"foo", "bar"})
//
// Notes:
//
// - Adding non-nil but empty input will be construed as "no fields"
//
// - Fields compose, they do not overwrite; if you want to start over, create a
// new OutputFields struct
func (o *OutputFields) AddFields(input []string) *OutputFields {
	ret := o
	if ret == nil {
		ret = new(OutputFields)
	}
	switch {
	case input == nil:
		// Do nothing

	case len(input) == 0:
		// Ensure we set to non-nil if it isn't already to capture that input is
		// not empty but fields are not being added
		if ret.fields == nil {
			ret.fields = make(map[string]bool)
		}

	case len(ret.fields) == 1 && ret.fields["*"]:
		// Again do nothing, there's nothing to add

	default:
		// Ensure the map is valid
		if ret.fields == nil {
			ret.fields = make(map[string]bool, len(input))
		}

		// Go through and add fields
		for _, k := range input {
			if k == "*" {
				ret.fields = map[string]bool{k: true}
				return ret
			}
			ret.fields[k] = true
		}
	}

	return ret
}

// Fields returns an alphabetical string slice of the fields in the map. The
// return value will be nil with hasSetFields false if fields are unset (e.g.
// we'd use the defaults in SelfOrDefaults), and non-nil (but empty if no fields
// are allowed) with hasSetFields true if fields have been configured. It is
// safe to call this on a nil object; it will return a nil slice and false for
// hasSetFields.
func (o *OutputFields) Fields() (fields []string, hasSetFields bool) {
	if o == nil || o.fields == nil {
		return nil, false
	}
	if len(o.fields) == 0 {
		return []string{}, true
	}
	ret := make([]string, 0, len(o.fields))
	for f := range o.fields {
		ret = append(ret, f)
	}
	sort.Strings(ret)
	return ret, true
}

// SelfOrDefaults returns either the output fields itself or the defaults for
// the given user. It is safe to call this on a nil object (it will always
// return defaults for the given user ID); if relying on this make sure to
// assign to the output, e.g.:
//
//	outFields = outFields.SelfOrDefaults("foo")
func (o *OutputFields) SelfOrDefaults(userId string) *OutputFields {
	ret := o
	if ret == nil {
		ret = new(OutputFields)
	}
	switch {
	case ret.fields != nil:
		// We have values set (which may be empty) so use those
		return ret

	case userId == "":
		// This shouldn't happen, and if it does, don't allow anything to be
		// output -- keep map empty and set to not-default so we use the empty
		// map
		ret.fields = make(map[string]bool)

	case userId == globals.AnonymousUserId:
		ret.fields = map[string]bool{
			globals.IdField:                          true,
			globals.ScopeField:                       true,
			globals.ScopeIdField:                     true,
			globals.PluginIdField:                    true,
			globals.PluginField:                      true,
			globals.NameField:                        true,
			globals.DescriptionField:                 true,
			globals.TypeField:                        true,
			globals.IsPrimaryField:                   true,
			globals.PrimaryAuthMethodIdField:         true,
			globals.AuthorizedActionsField:           true,
			globals.AuthorizedCollectionActionsField: true,
		}

	default:
		// Default behavior is to allow all fields
		ret.fields = map[string]bool{
			"*": true,
		}
	}

	return ret
}

// Has returns true if the field should be allowed; that is, it is explicitly
// allowed, or the fields contains *. It is safe to call this on a nil object
// (it will always return false).
func (o *OutputFields) Has(in string) bool {
	if o == nil || o.fields == nil {
		return false
	}
	return o.fields["*"] || o.fields[in]
}
