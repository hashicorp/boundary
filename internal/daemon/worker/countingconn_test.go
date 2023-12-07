// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package worker

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCountingConn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		writeBytes     []byte
		underlyingConn *testNetConn
	}{
		{
			name:       "noErrors",
			writeBytes: []byte("hello"),
			underlyingConn: &testNetConn{
				bytesToRead: 100,
				readErr:     false,
				writeErr:    false,
				closeErr:    false,
			},
		},
		{
			name:       "readErr",
			writeBytes: []byte("hello"),
			underlyingConn: &testNetConn{
				bytesToRead: 100,
				readErr:     true,
				writeErr:    false,
				closeErr:    false,
			},
		},
		{
			name:       "writeErr",
			writeBytes: []byte("hello"),
			underlyingConn: &testNetConn{
				bytesToRead: 100,
				readErr:     false,
				writeErr:    true,
				closeErr:    false,
			},
		},
		{
			name:       "closeErr",
			writeBytes: []byte("hello"),
			underlyingConn: &testNetConn{
				bytesToRead: 100,
				readErr:     false,
				writeErr:    false,
				closeErr:    true,
			},
		},
		{
			name:       "allErr",
			writeBytes: []byte("hello"),
			underlyingConn: &testNetConn{
				bytesToRead: 100,
				readErr:     true,
				writeErr:    true,
				closeErr:    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := countingConn{Conn: tt.underlyingConn}

			readBytes := make([]byte, tt.underlyingConn.bytesToRead)
			read, err := conn.Read(readBytes)
			require.True(t, tt.underlyingConn.readCalled)
			if tt.underlyingConn.readErr {
				require.Error(t, err)
				require.Equal(t, 1, read)
				require.EqualValues(t, 1, conn.bytesRead) // We still capture the bytes on error
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.underlyingConn.bytesToRead, read)
				require.EqualValues(t, tt.underlyingConn.bytesToRead, conn.bytesRead)
				require.Len(t, readBytes, tt.underlyingConn.bytesToRead)
			}

			written, err := conn.Write(tt.writeBytes)
			require.True(t, tt.underlyingConn.writeCalled)
			if tt.underlyingConn.writeErr {
				require.Error(t, err)
				require.Equal(t, 1, written)
				require.EqualValues(t, 1, conn.bytesWritten) // We still capture the bytes on error
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.writeBytes), written)
				require.EqualValues(t, len(tt.writeBytes), conn.bytesWritten)
			}

			err = conn.Close()
			require.True(t, tt.underlyingConn.closeCalled)
			if tt.underlyingConn.closeErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCountingConnConcurrentCalls(t *testing.T) {
	t.Parallel()

	bytesToRead := 100
	bytesToWrite := []byte("hello")

	concurrentReads := 1000
	concurrentWrites := 1000

	conn := &countingConn{Conn: &testNetConn{bytesToRead: bytesToRead}}

	wg := sync.WaitGroup{}
	wg.Add(concurrentReads)
	for i := 0; i < concurrentReads; i++ {
		go func() {
			defer wg.Done()
			in := make([]byte, bytesToRead)

			read, err := conn.Read(in)
			require.NoError(t, err)
			require.Equal(t, bytesToRead, read)
			require.Len(t, in, bytesToRead)
		}()
	}

	wg.Add(concurrentWrites)
	for i := 0; i < concurrentWrites; i++ {
		go func() {
			defer wg.Done()

			written, err := conn.Write(bytesToWrite)
			require.NoError(t, err)
			require.Equal(t, len(bytesToWrite), written)
		}()
	}

	wg.Wait()

	require.EqualValues(t, concurrentReads*bytesToRead, conn.BytesRead())
	require.EqualValues(t, concurrentWrites*len(bytesToWrite), conn.BytesWritten())
}

type testNetConn struct {
	net.Conn // So we don't have to implement the entire interface.

	// Test properties
	bytesToRead int
	readErr     bool
	writeErr    bool
	closeErr    bool

	// Test results
	readCalled  bool
	writeCalled bool
	closeCalled bool
}

func (t *testNetConn) Read(in []byte) (int, error) {
	t.readCalled = true
	if t.readErr {
		return 1, fmt.Errorf("oops, read error")
	}

	for i := 0; i < t.bytesToRead; i++ {
		in[i] = 10
	}

	return int(t.bytesToRead), nil
}

func (t *testNetConn) Write(in []byte) (int, error) {
	t.writeCalled = true
	if t.writeErr {
		return 1, fmt.Errorf("oops, write error")
	}

	return len(in), nil
}

func (t *testNetConn) Close() error {
	t.closeCalled = true
	if t.closeErr {
		return fmt.Errorf("oops, close error")
	}

	return nil
}
