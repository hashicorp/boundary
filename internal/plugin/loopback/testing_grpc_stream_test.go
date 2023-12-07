// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


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
