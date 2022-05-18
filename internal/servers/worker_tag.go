package servers

type TagSource string

const (
	ConfigurationTagSource TagSource = "configuration"
	ApiTagSource                     = "api"
)

func (t TagSource) isValid() bool {
	return t == ConfigurationTagSource || t == ApiTagSource
}
