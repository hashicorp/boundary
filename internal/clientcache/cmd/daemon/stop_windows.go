// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/version"
)

// stop will send a term signal to the daemon to shut down.
func (s *StopCommand) stop(ctx context.Context) error {
	const op = "daemon.(StopCommand).stop"
	switch {
	case util.IsNil(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "context is missing")
	}

	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
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
		s.UI.Warn(fmt.Sprintf("failed stopping the daemon through the handler: %q, now killing the process", errMsg))
	default:
		// there wasn't an error stopping it through the handler. No need to
		// force kill the process
		return nil
	}

	pidPath := filepath.Join(dotPath, pidFileName)
	p, err := pidFileInUse(ctx, pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.NotFound))
		}
		return errors.Wrap(ctx, err, op, errors.WithMsg("Unable to stop the daemon"))
	}
	if p == nil {
		return errors.New(ctx, errors.NotFound, op, "daemon process was not found")
	}

	if err := p.Kill(); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("killing the daemon"))
	}
	return nil
}

func stopThroughHandler(ctx context.Context, dotPath string) (*api.Error, error) {
	const op = "daemon.stopThroughHandler"

	sockAddr, err := daemon.SocketAddress(dotPath)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if err := client.SetAddr(sockAddr.String()); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// Because this is using the real lib it can pick up from stored locations
	// like the system keychain. Explicitly clear the token for now
	client.SetToken("")

	req, err := client.NewRequest(ctx, "POST", "/stop", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(daemon.VersionHeaderKey, version.Get().VersionNumber())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Decode(&struct{}{})
}
