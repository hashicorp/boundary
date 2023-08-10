// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build windows
// +build windows

package daemon

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/mitchellh/go-homedir"
)

const (
	dotDirectoryNameTemplate = "%s/.boundary"
	pidFileName              = "cache.pid"
	logFileName              = "cache.log"
)

// DefaultDotDirectory returns the default path to the boundary dot directory.
func DefaultDotDirectory(ctx context.Context) (string, error) {
	const op = "daemon.DefaultDotDirectory"
	homeDir, err := homedir.Dir()
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return fmt.Sprintf(dotDirectoryNameTemplate, homeDir), nil
}

// start will ensure this is the only daemon running and spin off a seperate process.
func (s *StartCommand) start(ctx context.Context, cmd commander, srv *server) error {
	const op = "daemon.(StartCommand).start"
	switch {
	case util.IsNil(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "context is missing")
	}
	return errors.New(ctx, errors.Internal, op, "daemon is not yet supported on windows.")
}
