// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/hashicorp/boundary/api/consts"
	pb "github.com/hashicorp/boundary/sdk/pbs/proxy"
	"github.com/hashicorp/boundary/sdk/wspb"
	"nhooyr.io/websocket"
)

func (p *ClientProxy) getWsConn(ctx context.Context) (*websocket.Conn, string, error) {
	conn, resp, err := websocket.Dial(
		ctx,
		fmt.Sprintf("ws://%s/v1/proxy", p.workerAddr),
		&websocket.DialOptions{
			HTTPClient:   p.controlClient,
			Subprotocols: []string{consts.WebsocketProtocolTcpProxyV2, consts.WebsocketProtocolTcpProxyV1},
		},
	)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "tls: internal error"):
			return nil, "", errors.New("session credentials were not accepted, or session is unauthorized")
		case strings.Contains(err.Error(), "connect: connection refused"):
			return nil, "", fmt.Errorf("unable to connect to worker at %s", p.workerAddr)
		default:
			return nil, "", fmt.Errorf("error dialing the worker: %w", err)
		}
	}

	if resp == nil {
		return nil, "", errors.New("response from worker is nil")
	}
	if resp.Header == nil {
		return nil, "", errors.New("response header is nil")
	}
	negProto := resp.Header.Get("Sec-WebSocket-Protocol")
	switch negProto {
	case consts.WebsocketProtocolTcpProxyV1, consts.WebsocketProtocolTcpProxyV2:
	default:
		return nil, "", fmt.Errorf("unexpected negotiated protocol: %s", negProto)
	}
	log.Println("negProto", negProto)
	return conn, negProto, nil
}

func (p *ClientProxy) sendSessionTeardown(ctx context.Context) error {
	handshake := pb.ClientHandshake{
		TofuToken: p.tofuToken,
		Command:   pb.HANDSHAKECOMMAND_HANDSHAKECOMMAND_SESSION_CANCEL,
	}
	wsConn, _, err := p.getWsConn(ctx)
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

func (p *ClientProxy) runTcpProxyV2(wsConn *websocket.Conn, listeningConn net.Conn) error {
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

	switch {
	case handshakeResult.GetSessionId() == "":
		p.cancel()
		return errors.New("no session id in handshake result")
	case handshakeResult.GetConnectionKey() == "":
		p.cancel()
		return errors.New("no connection key in handshake result")
	}

	if handshakeResult.GetConnectionsLeft() != -1 {
		p.connsLeftCh <- handshakeResult.GetConnectionsLeft()
	}

	// From this point on don't cancel as maybe it's recoverable by trying again
	// so leave the session alive

	dataPlaneTlsConf := p.clientTlsConf.Clone()
	dataPlaneTlsConf.NextProtos = []string{handshakeResult.GetSessionId(), consts.WebsocketProtocolTcpProxyV2}
	dialer := &tls.Dialer{Config: dataPlaneTlsConf}
	conn, err := dialer.DialContext(p.ctx, "tcp", p.workerAddr)
	if err != nil {
		log.Println("ERROR DIALING")
		return fmt.Errorf("error dialing worker for data connection: %w", err)
	}
	log.Println("DONE WITH DIAL")

	// Write our secret and expect an answer
	shake := []byte(fmt.Sprintf("%s-%s", handshakeResult.GetSessionId(), handshakeResult.GetConnectionKey()))
	n, err := conn.Write(shake)
	if err != nil {
		log.Println("BAD WRITE")
		return fmt.Errorf("error writing connection key: %w", err)
	}
	if n != len(shake) {
		log.Println("NOT ALL WRITTEN")
		return errors.New("not all bytes written")
	}
	log.Println("DONE WITH WRITE")
	var buf [2]byte
	n, err = conn.Read(buf[:])
	if err != nil {
		log.Println("BAD READ")
		return fmt.Errorf("error reading response from worker for data connection: %w", err)
	}
	if n != 2 {
		return errors.New("not all bytes read")
	}
	if buf[0] != 'O' || buf[1] != 'K' {
		log.Println("NOT OK")
		return errors.New("unexpected response from worker for data connection")
	}
	log.Println("GOT OK")

	localWg := new(sync.WaitGroup)
	localWg.Add(2)
	go func() {
		defer localWg.Done()
		io.Copy(conn, listeningConn)
		conn.Close()
		listeningConn.Close()
	}()
	go func() {
		defer localWg.Done()
		io.Copy(listeningConn, conn)
		listeningConn.Close()
		conn.Close()
	}()
	localWg.Wait()

	return nil
}
