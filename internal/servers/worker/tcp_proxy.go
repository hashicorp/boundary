package worker

import (
	"context"
	"io"
	"net"
	"net/url"
	"sync"

	"nhooyr.io/websocket"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

func (w *Worker) handleTcpProxyV1(connCtx context.Context, clientAddr *net.TCPAddr, conn *websocket.Conn, si *sessionInfo, connectionId, endpoint string) {
	si.RLock()
	sessionId := si.lookupSessionResponse.GetAuthorization().GetSessionId()
	si.RUnlock()

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
		w.logger.Error("error marking connection as connected", "error", err)
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
		w.logger.Debug("copy from client to endpoint done", "error", err)
	}()
	go func() {
		defer connWg.Done()
		_, err := io.Copy(tcpRemoteConn, netConn)
		tcpRemoteConn.Close()
		netConn.Close()
		w.logger.Debug("copy from endpoint to client done", "error", err)
	}()
	connWg.Wait()
}
