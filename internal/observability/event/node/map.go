package node

// PointerTag provides the pointerstructure pointer string to get/set a key
// within a map[string]interface{} along with its DataClassification and
// FilterOperation.
type PointerTag struct {

	// Pointer is the pointerstructure pointer string to get/set a key within a
	// map[string]interface{}  See: https://github.com/mitchellh/pointerstructure
	Pointer string

	// Classification is the DataClassification of data pointed to by the
	// Pointer
	Classification DataClassification

	// Filter is the FilterOperation to apply to the data pointed to by the
	// Pointer
	Filter FilterOperation
}

// Taggable defines an interface for taggable maps
type Taggable interface {

	// Tags will return a set of pointer tags for the map
	Tags() ([]PointerTag, error)
}
