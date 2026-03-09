// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"

	"github.com/hashicorp/boundary/internal/errors"
)

const (
	sockAddr = "socket/daemon.sock"

	// Currently we only allow the same user that started the boundary daemon
	// to connect to the socket to make requests to it.
	// In linux, sockets visible to the FS honor the perms of the dir they are in.
	// To create a new socket we must have read/write/list(execute) permissions on
	// the directory it is being created in.
	socketDirPerms = 0o700
	// To connect to a socket it must have read/write permissions
	socketPerms = 0o600
)

// listener provides a Listener on the daemon unix socket.
func listener(ctx context.Context, path string) (net.Listener, error) {
	const op = "daemon.listener"
	socketName := filepath.Join(path, sockAddr)
	if err := os.Remove(socketName); err != nil {
		// If the socket existed before and wasn't cleaned up delete it now.
		if !os.IsNotExist(err) {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	socketPath := filepath.Dir(socketName)
	if err := os.MkdirAll(socketPath, socketDirPerms); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to create boundary directory"))
	}

	l, err := net.Listen("unix", socketName)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Failed listening"))
	}
	if err := os.Chmod(socketName, socketPerms); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("changing socket permissiosn"))
	}
	return l, nil
}

// SocketAddress returns the unix socket *url.URL with the scheme set to 'unix'
// and the path set to the provided path. Verifying the path is valid is the
// responsibility of the caller.
func SocketAddress(path string) *url.URL {
	return &url.URL{
		Scheme: "unix",
		Path:   filepath.Join(path, sockAddr),
	}
}
