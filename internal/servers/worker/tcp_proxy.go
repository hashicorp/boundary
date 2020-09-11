package worker

import (
	"context"
	"io"
	"net"
	"sync"

	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/sessions"
	"nhooyr.io/websocket"
)

func (w *Worker) handleTcpProxyV1(jobCtx context.Context, conn *websocket.Conn, jobInfo *pb.Session) {
	remoteConn, err := net.Dial("tcp", jobInfo.Endpoint)
	if err != nil {
		w.logger.Error("error dialing endpoint", "error", err, "endpoint", jobInfo.Endpoint)
		conn.Close(websocket.StatusInternalError, "endpoint-dialing")
		return
	}
	// Assert this for better Go 1.11 splice support
	tcpRemoteConn := remoteConn.(*net.TCPConn)

	// Get a wrapped net.Conn so we can use io.Copy
	netConn := websocket.NetConn(jobCtx, conn, websocket.MessageBinary)

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
