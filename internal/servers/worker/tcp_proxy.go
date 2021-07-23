package worker

import (
	"context"
	"io"
	"net"
	"net/url"
	"sync"

	"nhooyr.io/websocket"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
)

func (w *Worker) handleTcpProxyV1(connCtx context.Context, clientAddr *net.TCPAddr, conn *websocket.Conn, si *sessionInfo, connectionId, endpoint string) {
	const op = "worker.(Worker).handleTcpProxyV1"
	ctx := context.TODO()
	si.RLock()
	sessionId := si.lookupSessionResponse.GetAuthorization().GetSessionId()
	si.RUnlock()

	sessionUrl, err := url.Parse(endpoint)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfo(event.I{"msg": "error parsing endpoint information", "session_id": sessionId, "endpoint": endpoint}))
		conn.Close(websocket.StatusInternalError, "cannot parse endpoint url")
		return
	}
	if sessionUrl.Scheme != "tcp" {
		event.WriteError(ctx, op, err, event.WithInfo(event.I{"session_id": sessionId, "endpoint": endpoint}))
		conn.Close(websocket.StatusInternalError, "invalid scheme for type")
		return
	}
	remoteConn, err := net.Dial("tcp", sessionUrl.Host)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfo(event.I{"msg": "error dialing endpoint", "endpoint": endpoint}))
		conn.Close(websocket.StatusInternalError, "endpoint dialing failed")
		return
	}
	// Assert this for better Go 1.11 splice support
	tcpRemoteConn := remoteConn.(*net.TCPConn)

	endpointAddr := tcpRemoteConn.RemoteAddr().(*net.TCPAddr)
	connectionInfo := &pbs.ConnectConnectionRequest{
		ConnectionId:       connectionId,
		ClientTcpAddress:   clientAddr.IP.String(),
		ClientTcpPort:      uint32(clientAddr.Port),
		EndpointTcpAddress: endpointAddr.IP.String(),
		EndpointTcpPort:    uint32(endpointAddr.Port),
		Type:               "tcp",
	}

	connStatus, err := w.connectConnection(connCtx, connectionInfo)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error marking connection as connected"))
		conn.Close(websocket.StatusInternalError, "failed to mark connection as connected")
		return
	}
	si.Lock()
	si.connInfoMap[connectionId].status = connStatus
	si.Unlock()

	// Get a wrapped net.Conn so we can use io.Copy
	netConn := websocket.NetConn(connCtx, conn, websocket.MessageBinary)

	connWg := new(sync.WaitGroup)
	connWg.Add(2)
	go func() {
		defer connWg.Done()
		_, err := io.Copy(netConn, tcpRemoteConn)
		netConn.Close()
		tcpRemoteConn.Close()
		event.WriteSysEvent(ctx, op, map[string]interface{}{"msg": "copy from client to endpoint done", "error": err})
	}()
	go func() {
		defer connWg.Done()
		_, err := io.Copy(tcpRemoteConn, netConn)
		tcpRemoteConn.Close()
		netConn.Close()
		event.WriteSysEvent(ctx, op, map[string]interface{}{"msg": "copy from endpoint to client done", "error": err})
	}()
	connWg.Wait()
}
