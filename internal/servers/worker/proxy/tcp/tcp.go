package tcp

import (
	"context"
	"io"
	"net"
	"net/url"
	"sync"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers/worker/proxy"
	"github.com/hashicorp/boundary/internal/servers/worker/session"
	"nhooyr.io/websocket"
)

func init() {
	err := proxy.RegisterHandler("tcp", handleTcpProxyV1)
	if err != nil {
		panic(err)
	}
}

// handleTcpProxyV1 creates a tcp proxy between the incoming websocket conn and the
// connection it creates with the remote endpoint. handleTcpProxyV1 sets the connectionId
// as connected in the repository.
//
// handleTcpProxyV1 blocks until an error (EOF on happy path) is received on either
// connection.
//
// All options are ignored.
func handleTcpProxyV1(ctx context.Context, conf proxy.Config, _ ...proxy.Option) {
	const op = "tcp.HandleTcpProxyV1"
	si := conf.SessionInfo
	si.RLock()
	sessionId := si.LookupSessionResponse.GetAuthorization().GetSessionId()
	si.RUnlock()

	conn := conf.ClientConn
	sessionUrl, err := url.Parse(conf.RemoteEndpoint)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error parsing endpoint information", "session_id", sessionId, "endpoint", conf.RemoteEndpoint))
		if err = conn.Close(websocket.StatusInternalError, "cannot parse endpoint url"); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
		}
		return
	}
	if sessionUrl.Scheme != "tcp" {
		event.WriteError(ctx, op, err, event.WithInfo("session_id", sessionId, "endpoint", conf.RemoteEndpoint))
		if err = conn.Close(websocket.StatusInternalError, "invalid scheme for type"); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
		}
		return
	}
	remoteConn, err := net.Dial("tcp", sessionUrl.Host)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error dialing endpoint", "endpoint", conf.RemoteEndpoint))
		if err = conn.Close(websocket.StatusInternalError, "endpoint dialing failed"); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
		}
		return
	}
	// Assert this for better Go 1.11 splice support
	tcpRemoteConn := remoteConn.(*net.TCPConn)

	endpointAddr := tcpRemoteConn.RemoteAddr().(*net.TCPAddr)
	connectionInfo := &pbs.ConnectConnectionRequest{
		ConnectionId:       conf.ConnectionId,
		ClientTcpAddress:   conf.ClientAddress.IP.String(),
		ClientTcpPort:      uint32(conf.ClientAddress.Port),
		EndpointTcpAddress: endpointAddr.IP.String(),
		EndpointTcpPort:    uint32(endpointAddr.Port),
		Type:               "tcp",
	}

	connStatus, err := session.ConnectConnection(ctx, conf.SessionClient, connectionInfo)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error marking connection as connected"))
		if err = conn.Close(websocket.StatusInternalError, "failed to mark connection as connected"); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
		}
		return
	}
	si.Lock()
	si.ConnInfoMap[conf.ConnectionId].Status = connStatus
	si.Unlock()

	// Get a wrapped net.Conn so we can use io.Copy
	netConn := websocket.NetConn(ctx, conn, websocket.MessageBinary)

	connWg := new(sync.WaitGroup)
	connWg.Add(2)
	go func() {
		defer connWg.Done()
		_, _ = io.Copy(netConn, tcpRemoteConn)
		_ = netConn.Close()
		_ = tcpRemoteConn.Close()
	}()
	go func() {
		defer connWg.Done()
		_, _ = io.Copy(tcpRemoteConn, netConn)
		_ = tcpRemoteConn.Close()
		_ = netConn.Close()
	}()
	connWg.Wait()
}
