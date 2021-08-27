package plugin

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// PublicId prefixes for the resources in the plugin package.
const (
	PluginVersionPrefix = "plgver"
)

func newPluginVersionId() (string, error) {
	id, err := db.NewPublicId(PluginVersionPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "plugin.newPluginVersionId")
	}
	return id, nil
}
