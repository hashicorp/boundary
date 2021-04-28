package perms

import "sort"

// OutputFieldsMap is used to store information about allowed output fields in
// grants
type OutputFieldsMap map[string]bool

// AddStrings adds the given fields and returns the map and whether or not the
// input included "*", which is used to shortcut some logic when checking ACL.
func (o OutputFieldsMap) AddFields(input []string) (ret OutputFieldsMap, starField bool) {
	switch {
	case len(input) == 0:
		if o == nil {
			return o, false
		}
		return o, o["*"]
	case o == nil:
		ret = make(OutputFieldsMap, len(input))
	case len(o) == 1 && o["*"]:
		return o, true
	default:
		ret = o
	}
	for _, k := range input {
		if k == "*" {
			starField = true
			ret = OutputFieldsMap{k: true}
			return
		}
		ret[k] = true
	}
	return
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
			"id":          true,
			"scope":       true,
			"scope_id":    true,
			"name":        true,
			"description": true,
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
	return o["*"] || o[in]
}
