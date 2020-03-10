package controller

import (
	"context"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/hashicorp/watchtower/internal/cmd/commands/controller/config"
)

type Config struct {
	*base.Server
	RawConfig   *config.Config
	BaseContext context.Context
}
