// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	"context"
	"fmt"
	"io"
	"sync"

	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc/metadata"
)

// getObjectStreamResponse is used to mock a message sent from the server to the client.
type getObjectStreamResponse struct {
	msg *plgpb.GetObjectResponse
	err error
}

// getObjectStream is used to mock the interactions between
// the client and server for the GetObject method.
type getObjectStream struct {
	client plgpb.StoragePluginService_GetObjectClient
	server plgpb.StoragePluginService_GetObjectServer

	// messages is used to mock the server sending messages to the client.
	messages chan *getObjectStreamResponse

	m            *sync.Mutex
	streamClosed bool

	ctx       context.Context
	cancelCtx context.CancelFunc
}

// IsStreamClosed returns true if the stream is closed.
func (s *getObjectStream) IsStreamClosed() bool {
	s.m.Lock()
	defer s.m.Unlock()
	return s.streamClosed
}

// Close closes the channels of the stream and sets the streamClosed flag to true.
// A closeStream is used to prevent the channels from being closed multiple times.
func (s *getObjectStream) Close() {
	s.m.Lock()
	defer s.m.Unlock()
	if s.streamClosed {
		return
	}
	// Cancel ctx to notify writers chan is closing
	s.cancelCtx()
	close(s.messages)
	s.streamClosed = true
}

// getObjectClient is used to mock the client stream
// interactions for the GetObject method.
type getObjectClient struct {
	// sentFromServer is used to mock the server sending messages to the client.
	sentFromServer chan *getObjectStreamResponse

	// closeStream is used to close the channels of the stream.
	// This is used to prevent the channels from being closed multiple times.
	// This is needed because the channel can be closed by the client or the server.
	closeStream func()

	// isStreamClosed is used to check if the stream is closed.
	// This is needed because the channel can be closed by the client or the server.
	isStreamClosed func() bool
}

// Recv will block until a message is received from the server.
// Recv will return io.EOF if the server closes the stream.
// Recv will return an error if the server sends an error.
func (c *getObjectClient) Recv() (*plgpb.GetObjectResponse, error) {
	resp, ok := <-c.sentFromServer
	if !ok {
		return nil, io.EOF
	}
	return resp.msg, resp.err
}

// Header should not be used.
// Header is implemeted to satisfy the grpc.ClientStream interface.
// Header will always return an empty metadata and an nil error.
func (c *getObjectClient) Header() (metadata.MD, error) {
	return make(metadata.MD), nil
}

// Trailer should not be used.
// Trailer is implemeted to satisfy the grpc.ClientStream interface.
// Trailer will always return an empty metadata.
func (c *getObjectClient) Trailer() metadata.MD {
	return make(metadata.MD)
}

// CloseSend will close the channel used to retrieve messages from
// the server. This will cause the Recv method to return io.EOF.
// CloseSend will return an error if the channel is already closed.
func (c *getObjectClient) CloseSend() error {
	if c.isStreamClosed() {
		return fmt.Errorf("stream is closed")
	}
	c.closeStream()
	return nil
}

// Context will always return a Background context.
func (c *getObjectClient) Context() context.Context {
	return context.Background()
}

// SendMsg should not be used.
// SendMsg is implemeted to satisfy the grpc.ClientStream interface.
// SendMsg will always return an nil error.
func (c *getObjectClient) SendMsg(m interface{}) error {
	return nil
}

// RecvMsg should not be used.
// RecvMsg is implemeted to satisfy the grpc.ClientStream interface.
// RecvMsg will always return an nil error.
func (c *getObjectClient) RecvMsg(m interface{}) error {
	return nil
}

// getObjectServer is used to mock the server stream
// interactions for the GetObject method.
type getObjectServer struct {
	ctx context.Context

	// sendToClient is used to mock the server sending messages to the client.
	sendToClient chan *getObjectStreamResponse

	// closeStream is used to close the channels of the stream.
	// This is used to prevent the channels from being closed multiple times.
	// This is needed because the channel can be closed by the client or the server.
	closeStream func()

	// isStreamClosed is used to check if the stream is closed.
	// This is needed because the channel can be closed by the client or the server.
	isStreamClosed func() bool

	// This is shared with the stream to prevent sending on closed channels
	m *sync.Mutex
}

// Send will send a message to the client.
// Send will return an error if the client closes the stream.
// Send will return an error if the response is nil.
func (s *getObjectServer) Send(resp *plgpb.GetObjectResponse) error {
	if resp == nil {
		return fmt.Errorf(`parameter arg "resp GetObjectResponse" cannot be nil`)
	}
	if s.isStreamClosed() {
		return fmt.Errorf("stream is closed")
	}

	s.m.Lock()
	defer s.m.Unlock()
	select {
	case s.sendToClient <- &getObjectStreamResponse{msg: resp}:
	case <-s.ctx.Done():
		return fmt.Errorf("stream is closed")
	}
	return nil
}

// SetHeader should not be used.
// SetHeader is implemeted to satisfy the grpc.ServerStream interface.
// SetHeader will always return an nil error.
func (s *getObjectServer) SetHeader(metadata.MD) error {
	return nil
}

// SendHeader should not be used.
// SendHeader is implemeted to satisfy the grpc.ServerStream interface.
// SendHeader will always return an nil error.
func (s *getObjectServer) SendHeader(metadata.MD) error {
	return nil
}

// SetTrailer should not be used.
// SetTrailer is implemeted to satisfy the grpc.ServerStream interface.
// SetTrailer will always return an nil error.
func (s *getObjectServer) SetTrailer(metadata.MD) {
}

// Context will always return a Background context.
func (s *getObjectServer) Context() context.Context {
	return context.Background()
}

// SendMsg allows sending GetObjectResponse messages to the client.
// SendMsg allows sending errors other than io.EOF to the client.
// Sending an error message will close the stream.
// SendMsg returns an invalid argument error if the message is not
// an error or GetObjectResponse.
// SendMsg will return an error if the stream is closed.
func (s *getObjectServer) SendMsg(m interface{}) error {
	switch msg := m.(type) {
	case *plgpb.GetObjectResponse:
		if s.isStreamClosed() {
			return fmt.Errorf("stream is closed")
		}
		s.m.Lock()
		defer s.m.Unlock()
		select {
		case s.sendToClient <- &getObjectStreamResponse{msg: msg}:
		case <-s.ctx.Done():
			return fmt.Errorf("stream is closed")
		}
	case error:
		if s.isStreamClosed() {
			return fmt.Errorf("stream is closed")
		}
		defer s.closeStream()
		s.m.Lock()
		defer s.m.Unlock()
		select {
		case s.sendToClient <- &getObjectStreamResponse{err: msg}:
		case <-s.ctx.Done():
			return fmt.Errorf("stream is closed")
		}
	default:
		return fmt.Errorf("invalid argument %v", m)
	}
	return nil
}

// RecvMsg should not be used.
// RecvMsg is implemeted to satisfy the grpc.ServerStream interface.
// RecvMsg will always return an nil error.
func (s *getObjectServer) RecvMsg(m interface{}) error {
	return nil
}

// newGetObjectStream will create a mock stream for the GetObject method.
// The client and server stream is mocked by creating a GetObjectResponse
// channel and an error channel that is shared between the client and server.
func newGetObjectStream() *getObjectStream {
	ctx, cnl := context.WithCancel(context.Background())
	stream := &getObjectStream{
		ctx:       ctx,
		cancelCtx: cnl,
		m:         new(sync.Mutex),
		messages:  make(chan *getObjectStreamResponse),
	}
	stream.client = &getObjectClient{
		sentFromServer: stream.messages,
		closeStream:    stream.Close,
		isStreamClosed: stream.IsStreamClosed,
	}
	stream.server = &getObjectServer{
		ctx:            ctx,
		sendToClient:   stream.messages,
		closeStream:    stream.Close,
		isStreamClosed: stream.IsStreamClosed,
		m:              stream.m,
	}
	return stream
}
