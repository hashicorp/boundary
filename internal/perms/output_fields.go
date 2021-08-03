package perms

import (
	"sort"

	"github.com/hashicorp/boundary/globals"
)

// OutputFieldsMap is used to store information about allowed output fields in
// grants
type OutputFieldsMap map[string]bool

// AddFields adds the given fields and returns the map.
func (o OutputFieldsMap) AddFields(input []string) (ret OutputFieldsMap) {
	switch {
	case len(input) == 0:
		if o == nil {
			return o
		}
		return o
	case o == nil:
		ret = make(OutputFieldsMap, len(input))
	case len(o) == 1 && o["*"]:
		return o
	default:
		ret = o
	}
	for _, k := range input {
		if k == "*" {
			ret = OutputFieldsMap{k: true}
			return
		}
		ret[k] = true
	}
	return
}

func (o OutputFieldsMap) HasAll() bool {
	return o["*"]
}

// Fields returns an alphabetical string slice of the fields in the map
func (o OutputFieldsMap) Fields() (ret []string) {
	if o == nil {
		return nil
	}
	if len(o) == 0 {
		return []string{}
	}
	ret = make([]string, 0, len(o))
	for f := range o {
		ret = append(ret, f)
	}
	sort.Strings(ret)
	return
}

// SelfOrDefaults returns either the fields map itself or the defaults for the
// given user
func (o OutputFieldsMap) SelfOrDefaults(userId string) OutputFieldsMap {
	switch {
	case o != nil:
		// We have values set (which may be empty) so use those
		return o
	case userId == "":
		// This shouldn't happen, and if it does, don't allow anything to be
		// output
		return OutputFieldsMap{}
	case userId == AnonymousUserId:
		return OutputFieldsMap{
			globals.IdField:                          true,
			globals.ScopeField:                       true,
			globals.ScopeIdField:                     true,
			globals.NameField:                        true,
			globals.DescriptionField:                 true,
			globals.TypeField:                        true,
			globals.IsPrimaryField:                   true,
			globals.PrimaryAuthMethodIdField:         true,
			globals.AuthorizedActionsField:           true,
			globals.AuthorizedCollectionActionsField: true,
		}
	default:
		return OutputFieldsMap{
			"*": true,
		}
	}
}

// Has returns true if the value exists; that is, it is directly in the map, or
// the map contains *
func (o OutputFieldsMap) Has(in string) bool {
	// Handle nil or empty case
	if len(o) == 0 {
		return false
	}
	return o.HasAll() || o[in]
}
