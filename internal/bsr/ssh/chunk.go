// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr"
)

const (
	Protocol bsr.Protocol = "SSH\x87"

	MaxPacketSize = 256 * 1024

	// Chunk types
	DataChunkType                  bsr.ChunkType = "DATA"
	BreakReqChunkType              bsr.ChunkType = "BREK"
	CancelTCPIPForwardReqChunkType bsr.ChunkType = "CTPF"
	DirectTCPIPReqChunkType        bsr.ChunkType = "DTCP"
	EnvReqChunkType                bsr.ChunkType = "ENVR"
	ExecReqChunkType               bsr.ChunkType = "EXEC"
	ExitSignalReqChunkType         bsr.ChunkType = "EXSG"
	ExitStatusReqChunkType         bsr.ChunkType = "EXST"
	ForwardedTCPIPReqChunkType     bsr.ChunkType = "FTCP"
	PtyReqChunkType                bsr.ChunkType = "PTYR"
	SessionReqChunkType            bsr.ChunkType = "SESS"
	ShellReqChunkType              bsr.ChunkType = "SHLL"
	SignalReqChunkType             bsr.ChunkType = "SGNL"
	SubsystemReqChunkType          bsr.ChunkType = "SUBS"
	TCPIPForwardReqChunkType       bsr.ChunkType = "TCPF"
	UnknownReqChunkType            bsr.ChunkType = "UNKR"
	WindowChangeReqChunkType       bsr.ChunkType = "WCHG"
	X11ForwardingReqChunkType      bsr.ChunkType = "X11F"
	X11ReqChunkType                bsr.ChunkType = "X11R"
	XonXoffReqChunkType            bsr.ChunkType = "XOXO"
)

// DataChunk contains the raw byte data from an SSH session
type DataChunk struct {
	bsr.BaseChunk
	Data []byte
}

// NewDataChunk constructs a DataChunk
func NewDataChunk(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, data []byte) (*DataChunk, error) {
	const op = "ssh.NewDataChunk"

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, DataChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &DataChunk{
		BaseChunk: *baseChunk,
		Data:      data,
	}, nil
}

// MarshalData returns the data for a DataChunk
func (c *DataChunk) MarshalData(_ context.Context) ([]byte, error) {
	return c.Data, nil
}
