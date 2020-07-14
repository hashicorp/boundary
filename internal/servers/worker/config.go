package worker

import (
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/hashicorp/watchtower/internal/cmd/config"
)

type Config struct {
	*base.Server
	RawConfig *config.Config
}
