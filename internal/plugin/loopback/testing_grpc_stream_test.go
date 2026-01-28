// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	tr "github.com/stretchr/testify/require"
)

func Test_GetObjectStream_Client(t *testing.T) {
	require := tr.New(t)

	t.Run("header", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.client)

		// Validate Header is not nil and does not return an error
		header, err := stream.client.Header()
		require.NotNil(header)
		require.NoError(err)
	})

	t.Run("trailer", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.client)

		// Validate Trailer is not nil
		trailer := stream.client.Trailer()
		require.NotNil(trailer)
	})

	t.Run("context", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.client)

		// Validate Context is not nil
		ctx := stream.client.Context()
		require.NotNil(ctx)
	})

	t.Run("sendMsg is ignored", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.client)

		// validate SendMsg does not write to the channel messages
		err := stream.client.SendMsg(nil)
		require.NoError(err)
		require.Empty(stream.messages)
	})

	t.Run("recvMsg does not read from the channel", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.client)

		// Validate RecvMsg does not read from the channel messages
		streamSize := len(stream.messages)
		var msg *getObjectStreamResponse
		err := stream.client.RecvMsg(msg)
		require.NoError(err)
		require.Nil(msg)
		require.Equal(streamSize, len(stream.messages))
	})

	t.Run("recv reads from the channel messages", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.client)

		// Validate Recv reads a message from the channel messages
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream.m.Lock()
			messages := stream.messages
			stream.m.Unlock()
			messages <- &getObjectStreamResponse{
				msg: &plgpb.GetObjectResponse{},
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := stream.client.Recv()
			require.NoError(err)
			require.NotNil(resp)
		}()
		wg.Wait()
		require.Empty(stream.messages)
	})

	t.Run("recv reads an error from the channel messages", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.client)

		// Validates Recv reads a error from the channel messages
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream.m.Lock()
			messages := stream.messages
			stream.m.Unlock()
			messages <- &getObjectStreamResponse{
				err: fmt.Errorf("mock error"),
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := stream.client.Recv()
			require.Error(err)
			require.Nil(resp)
		}()
		wg.Wait()
		require.Empty(stream.messages)
	})

	t.Run("closeSend closes the channel messages", func(t *testing.T) {
		stream := newGetObjectStream()
		require.NotNil(stream)
		require.NotNil(stream.client)
		require.False(stream.streamClosed)

		// Validate CloseSend does not return an error
		// Validate streamClosed is set to true
		// Validate the channel messages is closed
		err := stream.client.CloseSend()
		require.NoError(err)
		require.True(stream.streamClosed)
		_, ok := <-stream.messages
		require.False(ok)
		require.Empty(stream.messages)
	})

	t.Run("closeSend returns a stream is closed error", func(t *testing.T) {
		stream := newGetObjectStream()
		require.NotNil(stream)
		require.NotNil(stream.client)

		stream.Close()
		require.True(stream.streamClosed)

		// Validate CloseSend does return an error when the channel is closed
		// Validate streamClosed is set to true
		// Validate the channel messages is closed
		err := stream.client.CloseSend()
		require.Error(err)
		require.Contains(err.Error(), "stream is closed")
		require.True(stream.streamClosed)
		_, ok := <-stream.messages
		require.False(ok)
		require.Empty(stream.messages)
	})

	t.Run("recv returns EOF error on closed channel", func(t *testing.T) {
		stream := newGetObjectStream()
		require.NotNil(stream)
		require.NotNil(stream.client)

		stream.Close()
		require.True(stream.streamClosed)

		// Validate Recv returns EOF error when the channel is closed
		resp, err := stream.client.Recv()
		require.Equal(io.EOF, err)
		require.Nil(resp)
		require.Empty(stream.messages)
	})
}

func Test_GetObjectStream_Server(t *testing.T) {
	require := tr.New(t)

	t.Run("set header", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.server)

		// Validate SetHeader does not return an error
		err := stream.server.SetHeader(nil)
		require.NoError(err)
	})

	t.Run("send header", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.server)

		// Validate SendHeader does not return an error
		err := stream.server.SendHeader(nil)
		require.NoError(err)
	})

	t.Run("context", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.server)

		// Validate Context returns a context
		ctx := stream.server.Context()
		require.NotNil(ctx)
	})

	t.Run("stream is closed error", func(t *testing.T) {
		stream := newGetObjectStream()
		require.NotNil(stream)
		require.NotNil(stream.server)
		stream.Close()

		// Validate Send returns an error
		var err error
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
	})

	t.Run("receive empty message", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.server)

		// Validate RecvMsg does not read from the channel messages
		streamSize := len(stream.messages)
		var msg *getObjectStreamResponse
		err := stream.server.RecvMsg(msg)
		require.NoError(err)
		require.Nil(msg)
		require.Equal(streamSize, len(stream.messages))
	})

	t.Run("send writes to channel messages", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.server)

		// Validate Send writes to the channel messages
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := stream.server.Send(&plgpb.GetObjectResponse{})
			require.NoError(err)
			require.False(stream.streamClosed)
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
	})

	t.Run("sendMsg writes GetObjectResponse to channel messages", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.server)

		// Validate SendMsg writes to the channel messages for GetObjectResponse type
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := stream.server.SendMsg(&plgpb.GetObjectResponse{})
			require.NoError(err)
			require.False(stream.streamClosed)
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
	})

	t.Run("sendMsg writes error to close the channel", func(t *testing.T) {
		stream := newGetObjectStream()
		require.NotNil(stream)
		require.NotNil(stream.server)

		// Validate SendMsg closes the channel messages for error type
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := stream.server.SendMsg(fmt.Errorf("mock error"))
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
	})

	t.Run("sendMsg returns an error for unknown types", func(t *testing.T) {
		stream := newGetObjectStream()
		defer stream.Close()
		require.NotNil(stream)
		require.NotNil(stream.server)

		// Validate SendMsg returns an error for unknown message type
		err := stream.server.SendMsg(map[string]string{})
		require.Error(err)
		require.Contains(err.Error(), "invalid argument")
		require.False(stream.streamClosed)
	})
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

	t.Run("server receives error when client closes stream", func(t *testing.T) {
		stream := newGetObjectStream()

		require.NoError(stream.client.CloseSend())

		// Validate the server receives an error when the client closes the stream
		require.Eventually(func() bool {
			err := stream.server.Send(&plgpb.GetObjectResponse{})
			if err == nil {
				return false
			}
			return strings.Contains(err.Error(), "stream is closed")
		}, time.Second*10, time.Millisecond*500)

		require.True(stream.streamClosed)
		require.True(stream.IsStreamClosed())
		_, ok := <-stream.messages
		require.False(ok)
	})

	t.Run("client receives error when server sends error", func(t *testing.T) {
		stream := newGetObjectStream()

		// Validate the client receives an error when the server sends an error
		// Validate the channel messages is closed
		go func() {
			err := stream.server.SendMsg(fmt.Errorf("mock error"))
			require.NoError(err)
		}()

		require.Eventually(func() bool {
			resp, err := stream.client.Recv()
			if err == nil {
				return false
			}
			return resp == nil && strings.Contains(err.Error(), "mock error")
		}, time.Second*10, time.Millisecond*50)

		require.Eventually(func() bool {
			return stream.IsStreamClosed()
		}, time.Second*10, time.Millisecond*50)
	})
}
