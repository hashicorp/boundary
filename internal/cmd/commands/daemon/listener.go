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
)

const (
	sockAddr = "boundary_socket/boundary_daemon.sock"

	// Currently we only allow the same user that started the boundary daemon
	// to connect to the socket to make requests to it.
	// In linux, sockets visible to the FS honor the perms of the dir they are in.
	// To create a new socket we must have read/write/list(execute) permissions on
	// the directory it is being created in.
	socketDirPerms = 0o700
	// To connect to a socket it must have read/write permissions
	socketPerms = 0o600
)

func listen(ctx context.Context) (net.Listener, error) {
	const op = "daemon.listener"
	tmpDir := os.TempDir()
	socketName := filepath.Join(tmpDir, sockAddr)
	socketPath := filepath.Dir(socketName)

	if err := os.RemoveAll(socketPath); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to remove sock socketName"))
	}
	if err := os.Mkdir(socketPath, socketDirPerms); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to create socket directory"))
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

func daemonAddress() string {
	tmpDir := os.TempDir()
	return fmt.Sprintf("unix://%s", filepath.Join(tmpDir, sockAddr))
}
