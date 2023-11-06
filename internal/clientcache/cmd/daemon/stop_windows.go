// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/clientcache/internal/client"
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/util"
)

// stop will send a term signal to the daemon to shut down.
func (s *StopCommand) stop(ctx context.Context) error {
	switch {
	case util.IsNil(ctx):
		return errors.New("Invalid parameter provided to stop: context is missing")
	}

	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return fmt.Errorf("Error when getting default dot directory: %w", err)
	}

	apiErr, err := stopThroughHandler(ctx, dotPath)
	switch {
	case err != nil, apiErr != nil:
		var errMsg string
		if err != nil {
			errMsg = err.Error()
		} else if apiErr != nil {
			errMsg = apiErr.Message
		}
		s.UI.Warn(fmt.Sprintf("Failed stopping the daemon through the handler: %q, now killing the process", errMsg))
	default:
		// there wasn't an error stopping it through the handler. No need to
		// force kill the process
		return nil
	}

	pidPath := filepath.Join(dotPath, pidFileName)
	p, err := pidFileInUse(ctx, pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("Unable to stop the daemon: pid file not found.")
		}
		return fmt.Errorf("Error when trying to stop the daemon: %w", err)
	}
	if p == nil {
		return errors.New("Daemon process was not found.")
	}

	if err := p.Kill(); err != nil {
		return fmt.Errorf("Error when killing the process: %w.", err)
	}
	return nil
}

func stopThroughHandler(ctx context.Context, dotPath string) (*api.Error, error) {
	addr, err := daemon.SocketAddress(dotPath)
	if err != nil {
		return nil, fmt.Errorf("Error when retrieving the socket address: %w", err)
	}

	c, err := client.New(ctx, addr)
	if err != nil {
		return nil, err
	}
	_, apiErr, err := c.Post(ctx, "/v1/stop", nil)
	if err != nil {
		return nil, fmt.Errorf("Error when sending request to the daemon: %w.", err)
	}
	return apiErr, err
}
