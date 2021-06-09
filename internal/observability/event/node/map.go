package node

// PointerTag provides the pointerstructure pointer string to get/set a key
// within a map[string]interface{} along with its DataClassification and
// FilterOperation.
type PointerTag struct {
	Pointer        string
	Classification DataClassification
	Filter         FilterOperation
}

// Taggable defines an interface for taggable maps
type Taggable interface {
	// Tags will return a set of pointer tags for the map
	Tags() ([]PointerTag, error)
}
