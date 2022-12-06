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
	err := proxy.RegisterHandler("tcp", handleProxy)
	if err != nil {
		panic(err)
	}
}

// handleProxy creates a tcp proxy between the incoming websocket conn and the
// connection it creates with the remote endpoint. handleTcpProxyV1 sets the connectionId
// as connected in the repository.
//
// handleProxy blocks until an error (EOF on happy path) is received on either
// connection.
//
// All options are ignored.
func handleProxy(ctx context.Context, conn net.Conn, out *proxy.ProxyDialer, connId string, pi *anypb.Any) (proxy.ProxyConnFn, error) {
	const op = "tcp.HandleProxy"
	switch {
	case conn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "conn is nil")
	case out == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "proxy dialer is nil")
	case len(connId) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "connection id is empty")
	case pi != nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "protocol context Any proto is not nil")
	}
	remoteConn, err := out.Dial(ctx)
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
