package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/servers/worker/proxy"
	"github.com/hashicorp/boundary/internal/servers/worker/session"
	"nhooyr.io/websocket"
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
func handleProxy(ctx context.Context, conf proxy.Config, _ ...proxy.Option) error {
	conn := conf.ClientConn
	sessionUrl, err := url.Parse(conf.RemoteEndpoint)
	if err != nil {
		return fmt.Errorf("error parsing endpoint information: %w", err)
	}
	if sessionUrl.Scheme != "tcp" {
		return fmt.Errorf("invalid scheme for tcp proxy: %v", sessionUrl.Scheme)
	}
	remoteConn, err := net.Dial("tcp", sessionUrl.Host)
	if err != nil {
		return fmt.Errorf("error dialing endpoint: %w", err)
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
		UserClientIp:       conf.UserClientIp,
	}

	connStatus, err := session.ConnectConnection(ctx, conf.SessionClient, connectionInfo)
	if err != nil {
		return fmt.Errorf("error marking connection as connected: %w", err)
	}

	// Update connection info to set connection status
	conf.SessionInfo.Lock()
	conf.SessionInfo.ConnInfoMap[conf.ConnectionId].Status = connStatus
	conf.SessionInfo.Unlock()

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
	return nil
}
