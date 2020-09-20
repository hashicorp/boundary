package worker

import (
	"context"
	"io"
	"net"
	"net/url"
	"sync"

	"nhooyr.io/websocket"
)

func (w *Worker) handleTcpProxyV1(connCtx context.Context, conn *websocket.Conn, sessionId, endpoint string) {
	sessionUrl, err := url.Parse(endpoint)
	if err != nil {
		w.logger.Error("error parsing endpoint information", "error", err, "session_id", sessionId, "endpoint", endpoint)
		conn.Close(websocket.StatusInternalError, "cannot parse endpoint url")
		return
	}
	if sessionUrl.Scheme != "tcp" {
		w.logger.Error("invalid scheme for tcp proxy", "error", err, "session_id", sessionId, "endpoint", endpoint)
		conn.Close(websocket.StatusInternalError, "invalid scheme for type")
		return
	}
	remoteConn, err := net.Dial("tcp", sessionUrl.Host)
	if err != nil {
		w.logger.Error("error dialing endpoint", "error", err, "endpoint", endpoint)
		conn.Close(websocket.StatusInternalError, "endpoint-dialing")
		return
	}
	// Assert this for better Go 1.11 splice support
	tcpRemoteConn := remoteConn.(*net.TCPConn)

	// Get a wrapped net.Conn so we can use io.Copy
	netConn := websocket.NetConn(connCtx, conn, websocket.MessageBinary)

	connWg := new(sync.WaitGroup)
	connWg.Add(2)
	go func() {
		defer connWg.Done()
		_, err := io.Copy(netConn, tcpRemoteConn)
		w.logger.Debug("copy from client to endpoint done", "error", err)
	}()
	go func() {
		defer connWg.Done()
		_, err := io.Copy(tcpRemoteConn, netConn)
		w.logger.Debug("copy from endpoint to client done", "error", err)
	}()
	connWg.Wait()
}
