package worker

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
)

type Config struct {
	*base.Server
	RawConfig *config.Config
}
