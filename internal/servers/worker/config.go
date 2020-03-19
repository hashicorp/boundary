package worker

import (
	"context"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/hashicorp/watchtower/internal/cmd/commands/worker/config"
)

type Config struct {
	*base.Server
	RawConfig   *config.Config
	BaseContext context.Context
}
