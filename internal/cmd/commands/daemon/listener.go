// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/go-homedir"
)

const (
	sockAddr = ".boundary/boundary_daemon.sock"

	// Currently we only allow the same user that started the boundary daemon
	// to connect to the socket to make requests to it.
	// In linux, sockets visible to the FS honor the perms of the dir they are in.
	// To create a new socket we must have read/write/list(execute) permissions on
	// the directory it is being created in.
	socketDirPerms = 0o700
	// To connect to a socket it must have read/write permissions
	socketPerms = 0o600
)

// listener provides a listener on the daemon unix socket.
func listener(ctx context.Context) (net.Listener, error) {
	const op = "daemon.listener"

	homeDir, err := homedir.Dir()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	socketName := filepath.Join(homeDir, sockAddr)
	socketPath := filepath.Dir(socketName)
	if err := os.MkdirAll(socketPath, socketDirPerms); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to create boundary directory"))
	}

	l, err := net.Listen("unix", socketName)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if err := os.Chmod(socketName, socketPerms); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("changing socket permissiosn"))
	}
	return l, nil
}

// socketAddress returns the unix socket filename with a 'unix://'
func socketAddress() (string, error) {
	const op = "daemon.socketAddress"
	homeDir, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("unable to get home directory: %w", err)
	}
	return fmt.Sprintf("unix://%s", filepath.Join(homeDir, sockAddr)), nil
}
