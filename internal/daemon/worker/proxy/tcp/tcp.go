// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/types/known/anypb"
)

func init() {
	err := proxy.RegisterHandler(proxy.TcpHandlerName, handleProxy)
	if err != nil {
		panic(err)
	}
}

// handleProxy creates a tcp proxy between the incoming conn and the
// connection created by the ProxyDialer.
//
// handleProxy returns a ProxyConnFn which starts the copy between the
// connections and blocks until an error (EOF on happy path) is received on
// either connection.
func handleProxy(controlCtx context.Context, _ context.Context, _ proxy.DecryptFn, conn net.Conn, out *proxy.ProxyDialer, connId string, _ *anypb.Any, _ proxy.RecordingManager, _ ...proxy.Option) (proxy.ProxyConnFn, error) {
	const op = "tcp.HandleProxy"
	switch {
	case conn == nil:
		return nil, errors.New(controlCtx, errors.InvalidParameter, op, "conn is nil")
	case out == nil:
		return nil, errors.New(controlCtx, errors.InvalidParameter, op, "proxy dialer is nil")
	case len(connId) == 0:
		return nil, errors.New(controlCtx, errors.InvalidParameter, op, "connection id is empty")
	}
	remoteConn, err := out.Dial(controlCtx)
	if err != nil {
		return nil, err
	}

	return func() {
		connWg := new(sync.WaitGroup)
		connWg.Add(2)
		go func() {
			defer connWg.Done()
			_, _ = io.Copy(conn, remoteConn)
			_ = conn.Close()
			_ = remoteConn.Close()
		}()
		go func() {
			defer connWg.Done()
			_, _ = io.Copy(remoteConn, conn)
			_ = remoteConn.Close()
			_ = conn.Close()
		}()
		connWg.Wait()
	}, nil
}
