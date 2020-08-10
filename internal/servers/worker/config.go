package worker

import (
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/hashicorp/watchtower/internal/cmd/config"
)

type Config struct {
	// The base Server object, containing things shared between Controllers and
	// Workers
	*base.Server
	// The underlying configuration, passed in here to avoid duplicating values
	// everwyehere
	RawConfig *config.Config
}
