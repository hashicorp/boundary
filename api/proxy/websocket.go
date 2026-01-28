// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/hashicorp/boundary/api/consts"
	pb "github.com/hashicorp/boundary/sdk/pbs/proxy"
	"github.com/hashicorp/boundary/sdk/wspb"
)

func (p *ClientProxy) getWsConn(ctx context.Context) (*websocket.Conn, error) {
	conn, resp, err := websocket.Dial(
		ctx,
		fmt.Sprintf("ws://%s/v1/proxy", p.workerAddr),
		&websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: p.transport,
			},
			Subprotocols: []string{consts.WebsocketProtocolTcpProxyV1},
		},
	)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "tls: internal error"):
			return nil, errors.New("session credentials were not accepted, or session is unauthorized")
		case strings.Contains(err.Error(), "connect: connection refused"):
			return nil, fmt.Errorf("unable to connect to worker at %s", p.workerAddr)
		default:
			return nil, fmt.Errorf("error dialing the worker: %w", err)
		}
	}

	if resp == nil {
		return nil, errors.New("response from worker is nil")
	}
	if resp.Header == nil {
		return nil, errors.New("response header is nil")
	}
	negProto := resp.Header.Get("Sec-WebSocket-Protocol")
	if negProto != consts.WebsocketProtocolTcpProxyV1 {
		return nil, fmt.Errorf("unexpected negotiated protocol: %s", negProto)
	}
	return conn, nil
}

func (p *ClientProxy) sendSessionTeardown(ctx context.Context) error {
	handshake := pb.ClientHandshake{
		TofuToken: p.tofuToken,
		Command:   pb.HANDSHAKECOMMAND_HANDSHAKECOMMAND_SESSION_CANCEL,
	}
	wsConn, err := p.getWsConn(ctx)
	if err != nil {
		return fmt.Errorf("error fetching connection to send session teardown request to worker: %w", err)
	}
	if err := wspb.Write(ctx, wsConn, &handshake); err != nil {
		return fmt.Errorf("error sending teardown handshake to worker: %w", err)
	}
	wsConn.Close(websocket.StatusNormalClosure, "session teardown finished")

	return nil
}

func (p *ClientProxy) runTcpProxyV1(wsConn *websocket.Conn, listeningConn net.Conn) error {
	handshake := pb.ClientHandshake{TofuToken: p.tofuToken}
	if err := wspb.Write(p.ctx, wsConn, &handshake); err != nil {
		return fmt.Errorf("error sending handshake to worker: %w", err)
	}
	var handshakeResult pb.HandshakeResult
	if err := wspb.Read(p.ctx, wsConn, &handshakeResult); err != nil {
		switch {
		case strings.Contains(err.Error(), "unable to authorize connection"):
			// There's no reason to think we'd be able to authorize any more
			// connections after the first has failed. We don't cancel the
			// context here as existing connections may be fine.
			p.connsLeftCh <- 0
			return errors.New("unable to authorize connection")
		}
		switch {
		case strings.Contains(err.Error(), "tofu token not allowed"):
			// If our tofu token is not allowed something is wrong, and we
			// should cancel anything we have going.
			p.cancel()
			return errors.New("session is already in use")
		default:
			// If we can't handshake we can't do anything, so quit out
			p.cancel()
			return fmt.Errorf("error reading handshake result: %w", err)
		}
	}

	if handshakeResult.GetConnectionsLeft() != -1 {
		p.connsLeftCh <- handshakeResult.GetConnectionsLeft()
	}

	// Get a wrapped net.Conn so we can use io.Copy
	netConn := websocket.NetConn(p.ctx, wsConn, websocket.MessageBinary)

	localWg := new(sync.WaitGroup)
	localWg.Add(2)
	go func() {
		defer localWg.Done()
		io.Copy(netConn, listeningConn)
		netConn.Close()
		listeningConn.Close()
	}()
	go func() {
		defer localWg.Done()
		io.Copy(listeningConn, netConn)
		listeningConn.Close()
		netConn.Close()
	}()
	localWg.Wait()

	return nil
}
