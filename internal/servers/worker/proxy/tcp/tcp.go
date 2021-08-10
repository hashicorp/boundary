package tcp

import (
	"context"
	"io"
	"net"
	"net/url"
	"sync"

	"github.com/hashicorp/boundary/globals"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers/worker/common"
	"github.com/hashicorp/boundary/internal/servers/worker/proxy"
	"github.com/hashicorp/boundary/internal/servers/worker/session"
	"nhooyr.io/websocket"
)

func init() {
	err := proxy.RegisterHandler(globals.TcpProxyV1, HandleTcpProxyV1)
	if err != nil {
		panic(err)
	}
}

// HandleTcpProxyV1 creates a tcp proxy between the incoming websocket conn and the
// connection it creates with the remote endpoint. HandleTcpProxyV1 sets the connectionId
// as connected in the repository.
//
// HandleTcpProxyV1 blocks until an error (EOF on happy path) is received on either
// connection.
func HandleTcpProxyV1(connCtx context.Context,
	clientAddr *net.TCPAddr,
	conn *websocket.Conn,
	_ common.CredentialData,
	sessionClient pbs.SessionServiceClient,
	si *session.Info,
	connectionId, endpoint string) {
	const op = "tcp.HandleTcpProxyV1"
	ctx := context.TODO()
	si.RLock()
	sessionId := si.LookupSessionResponse.GetAuthorization().GetSessionId()
	si.RUnlock()

	sessionUrl, err := url.Parse(endpoint)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error parsing endpoint information", "session_id", sessionId, "endpoint", endpoint))
		_ = conn.Close(websocket.StatusInternalError, "cannot parse endpoint url")
		return
	}
	if sessionUrl.Scheme != "tcp" {
		event.WriteError(ctx, op, err, event.WithInfo("session_id", sessionId, "endpoint", endpoint))
		_ = conn.Close(websocket.StatusInternalError, "invalid scheme for type")
		return
	}
	remoteConn, err := net.Dial("tcp", sessionUrl.Host)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error dialing endpoint", "endpoint", endpoint))
		_ = conn.Close(websocket.StatusInternalError, "endpoint dialing failed")
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

	connStatus, err := session.ConnectConnection(connCtx, sessionClient, connectionInfo)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error marking connection as connected"))
		_ = conn.Close(websocket.StatusInternalError, "failed to mark connection as connected")
		return
	}
	si.Lock()
	si.ConnInfoMap[connectionId].Status = connStatus
	si.Unlock()

	// Get a wrapped net.Conn so we can use io.Copy
	netConn := websocket.NetConn(connCtx, conn, websocket.MessageBinary)

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
