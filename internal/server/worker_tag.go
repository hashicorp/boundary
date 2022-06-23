package server

// A Tag is a custom key/value pair which can be attached to a Worker.
// Multiple Tags may contain the same key and different values in which
// case both key/value pairs are valid.  Tags can be sourced from either the
// worker's configuration or the api. key/value pairs can be the same from
// different sources.
type Tag struct {
	Key   string
	Value string
}

type TagSource string

const (
	ConfigurationTagSource TagSource = "configuration"
	ApiTagSource           TagSource = "api"
)

func (t TagSource) isValid() bool {
	return t == ConfigurationTagSource || t == ApiTagSource
}

func (t TagSource) String() string {
	return string(t)
}
