// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package cache

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

// stop will send a term signal to the cache to shut down.
func (c *StopCommand) stop(ctx context.Context) error {
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
		c.UI.Warn(fmt.Sprintf("Failed stopping the cache through the handler: %q, now killing the process", errMsg))
	default:
		// there wasn't an error stopping it through the handler. No need to
		// force kill the process
		return nil
	}

	pidPath := filepath.Join(dotPath, pidFileName)
	p, err := pidFileInUse(ctx, pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("Unable to stop the cache: pid file not found.")
		}
		return fmt.Errorf("Error when trying to stop the cache: %w", err)
	}
	if p == nil {
		return errors.New("Cache process was not found.")
	}

	if err := p.Kill(); err != nil {
		return fmt.Errorf("Error when killing the process: %w.", err)
	}
	return nil
}

func stopThroughHandler(ctx context.Context, dotPath string) (*api.Error, error) {
	addr := daemon.SocketAddress(dotPath)
	c, err := client.New(ctx, addr)
	if err != nil {
		return nil, err
	}
	resp, err := c.Post(ctx, "/v1/stop", nil)
	if err != nil {
		return nil, fmt.Errorf("Error when sending request to the cache: %w.", err)
	}
	apiErr, err := resp.Decode(nil)
	return apiErr, err
}
