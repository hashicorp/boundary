// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package loopback

import (
	"fmt"
	"io"
	"sync"
	"testing"

	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	tr "github.com/stretchr/testify/require"
)

func Test_GetObjectStream_Client(t *testing.T) {
	require := tr.New(t)

	stream := newGetObjectStream()
	require.NotNil(stream)
	require.NotNil(stream.client)

	// Validate Header is not nil and does not return an error
	header, err := stream.client.Header()
	require.NotNil(header)
	require.NoError(err)

	// Validate Trailer is not nil
	trailer := stream.client.Trailer()
	require.NotNil(trailer)

	// Validate Context is not nil
	ctx := stream.client.Context()
	require.NotNil(ctx)

	// validate SendMsg does not write to the channel messages
	err = stream.client.SendMsg(nil)
	require.NoError(err)
	require.Empty(stream.messages)

	// Validate RecvMsg does not read from the channel messages
	streamSize := len(stream.messages)
	var msg *getObjectStreamResponse
	err = stream.client.RecvMsg(msg)
	require.NoError(err)
	require.Nil(msg)
	require.Equal(streamSize, len(stream.messages))

	// Validate Recv reads a message from the channel messages
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		stream.messages <- &getObjectStreamResponse{
			msg: &plgpb.GetObjectResponse{},
		}
	}()
	go func() {
		defer wg.Done()
		resp, err := stream.client.Recv()
		require.NoError(err)
		require.NotNil(resp)
	}()
	wg.Wait()

	// Validates Recv reads a error from the channel messages
	wg.Add(1)
	go func() {
		stream.messages <- &getObjectStreamResponse{
			err: fmt.Errorf("mock error"),
		}
	}()
	go func() {
		defer wg.Done()
		resp, err := stream.client.Recv()
		require.Error(err)
		require.Nil(resp)
	}()
	wg.Wait()

	// Validate CloseSend does not return an error
	// Validate streamClosed is set to true
	// Validate the channel messages is closed
	var ok bool
	err = stream.client.CloseSend()
	require.NoError(err)
	require.True(stream.streamClosed)
	_, ok = <-stream.messages
	require.False(ok)

	// Validate CloseSend does return an error when the channel is closed
	// Validate streamClosed is set to true
	// Validate the channel messages is closed
	err = stream.client.CloseSend()
	require.Error(err)
	require.Contains(err.Error(), "stream is closed")
	require.True(stream.streamClosed)
	_, ok = <-stream.messages
	require.False(ok)

	// Validate Recv returns EOF error when the channel is closed
	resp, err := stream.client.Recv()
	require.Equal(io.EOF, err)
	require.Nil(resp)
}

func Test_GetObjectStream_Server(t *testing.T) {
	require := tr.New(t)

	stream := newGetObjectStream()
	require.NotNil(stream)
	require.NotNil(stream.server)

	// Validate SetHeader does not return an error
	err := stream.server.SetHeader(nil)
	require.NoError(err)

	// Validate SendHeader does not return an error
	err = stream.server.SendHeader(nil)
	require.NoError(err)

	// Validate Context returns a context
	ctx := stream.server.Context()
	require.NotNil(ctx)

	// Validate RecvMsg does not read from the channel messages
	streamSize := len(stream.messages)
	var msg *getObjectStreamResponse
	err = stream.server.RecvMsg(msg)
	require.NoError(err)
	require.Nil(msg)
	require.Equal(streamSize, len(stream.messages))

	// Validate Send writes to the channel messages
	var wg sync.WaitGroup
	go func() {
		err = stream.server.Send(&plgpb.GetObjectResponse{})
		require.NoError(err)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, ok := <-stream.messages
		require.True(ok)
		require.NotNil(resp)
		require.NotNil(resp.msg)
		require.Nil(resp.err)
	}()
	wg.Wait()

	// Validate Send returns an error when the channel is closed
	stream.Close()
	require.True(stream.streamClosed)
	err = stream.server.Send(&plgpb.GetObjectResponse{})
	require.Error(err)
	require.Contains(err.Error(), "stream is closed")

	// Validate SendMsg returns an error when the channel is closed
	err = stream.server.SendMsg(&plgpb.GetObjectResponse{})
	require.Error(err)
	require.Contains(err.Error(), "stream is closed")
	err = stream.server.SendMsg(fmt.Errorf("mock error"))
	require.Error(err)
	require.Contains(err.Error(), "stream is closed")

	// Reset stream
	stream = newGetObjectStream()

	// Validate SendMsg returns an error for unknown message type
	err = stream.server.SendMsg(map[string]string{})
	require.False(stream.streamClosed)
	require.Error(err)
	require.Contains(err.Error(), "invalid argument")

	// Validate SendMsg writes to the channel messages for GetObjectResponse type
	go func() {
		err = stream.server.SendMsg(&plgpb.GetObjectResponse{})
		require.NoError(err)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, ok := <-stream.messages
		require.True(ok)
		require.NotNil(resp)
		require.NotNil(resp.msg)
		require.Nil(resp.err)
	}()
	wg.Wait()

	// Validate SendMsg closes the channel messages for error type
	go func() {
		err = stream.server.SendMsg(fmt.Errorf("mock error"))
		require.NoError(err)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, ok := <-stream.messages
		require.True(ok)
		require.NotNil(resp)
		require.NotNil(resp.err)
		require.Nil(resp.msg)
	}()
	wg.Wait()
	require.True(stream.streamClosed)
	_, ok := <-stream.messages
	require.False(ok)
}

func TestNewGetObjectStream(t *testing.T) {
	require := tr.New(t)

	stream := newGetObjectStream()
	require.NotNil(stream)
	require.NotNil(stream.m)
	require.NotNil(stream.client)
	require.NotNil(stream.server)
	require.NotNil(stream.messages)
	require.False(stream.streamClosed)
	require.False(stream.IsStreamClosed())

	// Validate Close() closes the channel messages
	stream.Close()
	require.True(stream.streamClosed)
	require.True(stream.IsStreamClosed())
	_, ok := <-stream.messages
	require.False(ok)
}

func Test_PutObjectStream_Client(t *testing.T) {
	require := tr.New(t)

	stream := newPutObjectStream()
	require.NotNil(stream)
	require.NotNil(stream.client)

	// Validate Header is not nil and does not return an error
	header, err := stream.client.Header()
	require.NotNil(header)
	require.NoError(err)

	// Validate Trailer is not nil
	trailer := stream.client.Trailer()
	require.NotNil(trailer)

	// Validate Context is not nil
	ctx := stream.client.Context()
	require.NotNil(ctx)

	// Validate SendMsg does not write to the channel requests
	err = stream.client.SendMsg(nil)
	require.NoError(err)
	require.Empty(stream.requests)

	// Validate RecvMsg does not read from the channel requests
	streamSize := len(stream.requests)
	var msg *putObjectStreamResponse
	err = stream.client.RecvMsg(msg)
	require.NoError(err)
	require.Nil(msg)
	require.Equal(streamSize, len(stream.requests))

	// Validate Send returns an error when the request is nil
	err = stream.client.Send(nil)
	require.Error(err)

	// Validate Send writes to the channel requests
	var wg sync.WaitGroup
	go func() {
		err = stream.client.Send(&plgpb.PutObjectRequest{})
		require.NoError(err)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, ok := <-stream.requests
		require.True(ok)
		require.NotNil(req)
		require.NotNil(req.msg)
		require.Nil(req.err)
	}()
	wg.Wait()

	// Validate CloseSend does not return an error
	// Validate clientClosed is set to true
	// Validate the channel requests is closed
	var ok bool
	err = stream.client.CloseSend()
	require.NoError(err)
	require.True(stream.clientClosed)
	_, ok = <-stream.requests
	require.False(ok)

	// Validate CloseSend does return an error when the channel is closed
	// Validate clientClosed is set to true
	// Validate the channel requests is closed
	err = stream.client.CloseSend()
	require.Error(err)
	require.Contains(err.Error(), "stream is closed")
	require.True(stream.clientClosed)
	_, ok = <-stream.requests
	require.False(ok)

	// Validate Send returns an error when the channel is closed
	err = stream.client.Send(&plgpb.PutObjectRequest{})
	require.Error(err)
	require.Contains(err.Error(), "stream is closed")
	require.Empty(stream.requests)

	// Reset stream
	stream = newPutObjectStream()

	// Validate CloseAndRecv returns an EOF error when the channel responses is closed
	// Validate CloseAndRecv closes the channel requests
	stream.CloseServer()
	resp, err := stream.client.CloseAndRecv()
	require.Equal(io.EOF, err)
	require.Nil(resp)
	require.True(stream.clientClosed)
	require.True(stream.IsClientClosed())
	require.True(stream.serverClosed)
	require.True(stream.IsServerClosed())
}

func Test_PutObjectStream_Server(t *testing.T) {
	require := tr.New(t)

	stream := newPutObjectStream()
	require.NotNil(stream)
	require.NotNil(stream.server)

	// Validate SetHeader does not return an error
	err := stream.server.SetHeader(nil)
	require.NoError(err)

	// Validate SendHeader does not return an error
	err = stream.server.SendHeader(nil)
	require.NoError(err)

	// Validate Context returns a context
	ctx := stream.server.Context()
	require.NotNil(ctx)

	// Validate RecvMsg does not read from the channel requests
	streamSize := len(stream.requests)
	var msg *putObjectStreamRequest
	err = stream.server.RecvMsg(msg)
	require.NoError(err)
	require.Nil(msg)
	require.Equal(streamSize, len(stream.requests))

	// Validate SendMsg returns an error for unknown message types
	err = stream.server.SendMsg(map[string]string{})
	require.Error(err)
	require.Contains(err.Error(), "invalid argument")

	// Validate SendMsg does write a message to the channel responses
	var wg sync.WaitGroup
	go func() {
		err = stream.server.SendMsg(&plgpb.PutObjectResponse{})
		require.NoError(err)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, ok := <-stream.responses
		require.True(ok)
		require.NotNil(resp)
		require.NotNil(resp.msg)
		require.Nil(resp.err)
	}()
	wg.Wait()

	// Validate SendMsg does write a error to the channel responses
	// Validate SendMsg closes the channel responses
	go func() {
		err = stream.server.SendMsg(fmt.Errorf("mock error"))
		require.NoError(err)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, ok := <-stream.responses
		require.True(ok)
		require.NotNil(resp)
		require.NotNil(resp.err)
		require.Nil(resp.msg)
	}()
	wg.Wait()
	_, ok := <-stream.responses
	require.False(ok)
	require.True(stream.serverClosed)
	require.True(stream.IsServerClosed())

	// Validate SendMsg does return an error when the channel responses is closed
	err = stream.server.SendMsg(&plgpb.PutObjectResponse{})
	require.Error(err)
	require.Contains(err.Error(), "stream is closed")
	err = stream.server.SendMsg(fmt.Errorf("mock error"))
	require.Error(err)
	require.Contains(err.Error(), "stream is closed")

	// Validate SendAndClose returns an error when response is nil
	err = stream.server.SendAndClose(nil)
	require.Error(err)

	// Validate SendAndClose returns an error when the channel responses is closed
	err = stream.server.SendAndClose(&plgpb.PutObjectResponse{})
	require.Error(err)
	require.Contains(err.Error(), "stream is closed")

	// Reset stream
	stream = newPutObjectStream()

	// Validate SendAndClose closes the responses channel
	go func() {
		err = stream.server.SendAndClose(&plgpb.PutObjectResponse{})
		require.NoError(err)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, ok := <-stream.responses
		require.True(ok)
		require.NotNil(resp)
		require.NotNil(resp.msg)
		require.Nil(resp.err)
	}()
	wg.Wait()
	require.True(stream.serverClosed)
	require.True(stream.IsServerClosed())
	_, ok = <-stream.responses
	require.False(ok)
}

func TestNewPutObjectStream(t *testing.T) {
	require := tr.New(t)

	stream := newPutObjectStream()
	require.NotNil(stream)
	require.NotNil(stream.m)
	require.NotNil(stream.client)
	require.NotNil(stream.server)
	require.NotNil(stream.requests)
	require.NotNil(stream.responses)
	require.False(stream.clientClosed)
	require.False(stream.IsClientClosed())
	require.False(stream.serverClosed)
	require.False(stream.IsServerClosed())

	// Validate CloseClient() closes the requests channel
	stream.CloseClient()
	require.True(stream.clientClosed)
	require.True(stream.IsClientClosed())
	_, ok := <-stream.requests
	require.False(ok)

	// Validate CloseServer() closes the responses channel
	stream.CloseServer()
	require.True(stream.serverClosed)
	require.True(stream.IsServerClosed())
	_, ok = <-stream.responses
	require.False(ok)
}

func Test_GetObjectStream(t *testing.T) {
	require := tr.New(t)

	stream := newGetObjectStream()

	// Validate the server receives an error when the client closes the stream
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			err := stream.server.Send(&plgpb.GetObjectResponse{})
			if err == nil {
				continue
			}
			require.Error(err)
			require.Contains(err.Error(), "stream is closed")
			break
		}
	}()
	stream.client.CloseSend()
	wg.Wait()
	require.True(stream.streamClosed)
	require.True(stream.IsStreamClosed())
	_, ok := <-stream.messages
	require.False(ok)

	// Reset Stream
	stream = newGetObjectStream()

	// Validate the client recieves an error when the server sends an error
	// Validate the channel messages is closed
	go func() {
		err := stream.server.SendMsg(fmt.Errorf("mock error"))
		require.NoError(err)
	}()
	resp, err := stream.client.Recv()
	require.Nil(resp)
	require.Error(err)
	require.Contains(err.Error(), "mock error")
	require.True(stream.streamClosed)
	require.True(stream.IsStreamClosed())
	_, ok = <-stream.messages
	require.False(ok)
}

func Test_PutObjectStream(t *testing.T) {
	require := tr.New(t)

	stream := newPutObjectStream()

	// Validate the client recieves the response when the server closes the stream
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			resp, err := stream.client.CloseAndRecv()
			require.NotNil(resp)
			require.NoError(err)
			break
		}
	}()
	go func() {
		defer wg.Done()
		err := stream.server.SendAndClose(&plgpb.PutObjectResponse{})
		require.NoError(err)
	}()
	wg.Wait()
	require.True(stream.clientClosed)
	require.True(stream.IsClientClosed())
	require.True(stream.serverClosed)
	require.True(stream.IsServerClosed())
	_, ok := <-stream.requests
	require.False(ok)
	_, ok = <-stream.responses
	require.False(ok)

	// Reset Stream
	stream = newPutObjectStream()

	// Validate the client recieves an error when the server sends an error
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			resp, err := stream.client.CloseAndRecv()
			require.Nil(resp)
			require.Error(err)
			require.Contains(err.Error(), "mock error")
			break
		}
	}()
	go func() {
		defer wg.Done()
		err := stream.server.SendMsg(fmt.Errorf("mock error"))
		require.NoError(err)
	}()
	wg.Wait()
	require.True(stream.clientClosed)
	require.True(stream.IsClientClosed())
	require.True(stream.serverClosed)
	require.True(stream.IsServerClosed())
	_, ok = <-stream.requests
	require.False(ok)
	_, ok = <-stream.responses
	require.False(ok)

	// Reset Stream
	stream = newPutObjectStream()

	// Validate the server recieves an EOF error when the client closes the stream
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			req, err := stream.server.Recv()
			if err != nil {
				require.Nil(req)
				require.Equal(io.EOF, err)
				break
			}
		}
	}()
	go func() {
		wg.Done()
		err := stream.client.CloseSend()
		require.NoError(err)
	}()
	wg.Wait()
	require.True(stream.clientClosed)
	require.True(stream.IsClientClosed())
	require.False(stream.serverClosed)
	require.False(stream.IsServerClosed())
	_, ok = <-stream.requests
	require.False(ok)
}
