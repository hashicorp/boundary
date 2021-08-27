package host

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// PublicId prefixes for the resources in the plugin package.
const (
	PluginPrefix = "plgh"
)

func newPluginId() (string, error) {
	id, err := db.NewPublicId(PluginPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "plugin.newPluginId")
	}
	return id, nil
}
