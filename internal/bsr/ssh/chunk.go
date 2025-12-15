// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr"
	pssh "github.com/hashicorp/boundary/internal/bsr/gen/ssh/v1"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"google.golang.org/protobuf/proto"
)

func init() {
	for _, ct := range []bsr.ChunkType{
		DataChunkType,
		BreakReqChunkType,
		CancelTCPIPForwardReqChunkType,
		DirectTCPIPReqChunkType,
		EnvReqChunkType,
		ExecReqChunkType,
		ExitSignalReqChunkType,
		ExitStatusReqChunkType,
		ForwardedTCPIPReqChunkType,
		PtyReqChunkType,
		SessionReqChunkType,
		ShellReqChunkType,
		SignalReqChunkType,
		SubsystemReqChunkType,
		TCPIPForwardReqChunkType,
		WindowChangeReqChunkType,
		X11ForwardingReqChunkType,
		X11ReqChunkType,
		XonXoffReqChunkType,
		UnknownReqChunkType,
	} {
		if err := bsr.RegisterChunkType(Protocol, ct, DecodeChunk); err != nil {
			panic(err)
		}
	}
}

const (
	// Protocol is used to identify chunks that are recorded from SSH.
	Protocol bsr.Protocol = "BSSH"

	// MaxPacketSize is used by the DataWriter to determine if SSH data should
	// be broken into multiple chunks.
	MaxPacketSize = 256 * 1024
)

// Chunk types
const (
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
	*bsr.BaseChunk
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
		BaseChunk: baseChunk,
		Data:      data,
	}, nil
}

// MarshalData returns the data for a DataChunk
func (c *DataChunk) MarshalData(_ context.Context) ([]byte, error) {
	return c.Data, nil
}

// DecodeChunk will decode any known SSH Chunk type. If the chunk type is
// not an ssh chunk type, and error is returned.
func DecodeChunk(_ context.Context, bc *bsr.BaseChunk, data []byte) (bsr.Chunk, error) {
	const op = "ssh.DecodeChunk"

	if is.Nil(bc) {
		return nil, fmt.Errorf("%s: nil base chunk: %w", op, bsr.ErrInvalidParameter)
	}

	if bc.Protocol != Protocol {
		return nil, fmt.Errorf("%s: invalid protocol %s", op, bc.Protocol)
	}

	switch bc.Type {
	case DataChunkType:
		return &DataChunk{
			BaseChunk: bc,
			Data:      data,
		}, nil
	}

	if len(data) <= 0 {
		return nil, fmt.Errorf("%s: not enough data", op)
	}

	switch bc.Type {
	case BreakReqChunkType:
		mm := &pssh.BreakRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &BreakRequest{
			BaseChunk:    bc,
			BreakRequest: mm,
		}, nil
	case CancelTCPIPForwardReqChunkType:
		mm := &pssh.CancelTCPIPForwardRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &CancelTCPIPForwardRequest{
			BaseChunk:                 bc,
			CancelTCPIPForwardRequest: mm,
		}, nil
	case DirectTCPIPReqChunkType:
		mm := &pssh.DirectTCPIPRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &DirectTCPIPRequest{
			BaseChunk:          bc,
			DirectTCPIPRequest: mm,
		}, nil
	case EnvReqChunkType:
		mm := &pssh.EnvRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &EnvRequest{
			BaseChunk:  bc,
			EnvRequest: mm,
		}, nil
	case ExecReqChunkType:
		mm := &pssh.ExecRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ExecRequest{
			BaseChunk:   bc,
			ExecRequest: mm,
		}, nil
	case ExitSignalReqChunkType:
		mm := &pssh.ExitSignalRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ExitSignalRequest{
			BaseChunk:         bc,
			ExitSignalRequest: mm,
		}, nil
	case ExitStatusReqChunkType:
		mm := &pssh.ExitStatusRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ExitStatusRequest{
			BaseChunk:         bc,
			ExitStatusRequest: mm,
		}, nil
	case ForwardedTCPIPReqChunkType:
		mm := &pssh.ForwardedTCPIPRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ForwardedTCPIPRequest{
			BaseChunk:             bc,
			ForwardedTCPIPRequest: mm,
		}, nil
	case PtyReqChunkType:
		mm := &pssh.PtyRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &PtyRequest{
			BaseChunk:  bc,
			PtyRequest: mm,
		}, nil
	case SessionReqChunkType:
		mm := &pssh.SessionRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &SessionRequest{
			BaseChunk:      bc,
			SessionRequest: mm,
		}, nil
	case ShellReqChunkType:
		mm := &pssh.ShellRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ShellRequest{
			BaseChunk:    bc,
			ShellRequest: mm,
		}, nil
	case SignalReqChunkType:
		mm := &pssh.SignalRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &SignalRequest{
			BaseChunk:     bc,
			SignalRequest: mm,
		}, nil
	case SubsystemReqChunkType:
		mm := &pssh.SubsystemRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &SubsystemRequest{
			BaseChunk:        bc,
			SubsystemRequest: mm,
		}, nil
	case TCPIPForwardReqChunkType:
		mm := &pssh.TCPIPForwardRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &TCPIPForwardRequest{
			BaseChunk:           bc,
			TCPIPForwardRequest: mm,
		}, nil
	case WindowChangeReqChunkType:
		mm := &pssh.WindowChangeRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &WindowChangeRequest{
			BaseChunk:           bc,
			WindowChangeRequest: mm,
		}, nil
	case X11ForwardingReqChunkType:
		mm := &pssh.X11ForwardingRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &X11ForwardingRequest{
			BaseChunk:            bc,
			X11ForwardingRequest: mm,
		}, nil
	case X11ReqChunkType:
		mm := &pssh.X11Request{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &X11Request{
			BaseChunk:  bc,
			X11Request: mm,
		}, nil
	case XonXoffReqChunkType:
		mm := &pssh.XonXoffRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &XonXoffRequest{
			BaseChunk:      bc,
			XonXoffRequest: mm,
		}, nil
	case UnknownReqChunkType:
		mm := &pssh.UnknownRequest{}
		if err := proto.Unmarshal(data, mm); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &UnknownRequest{
			BaseChunk:      bc,
			UnknownRequest: mm,
		}, nil

	default:
		return nil, fmt.Errorf("%s: unsupported chunk type %s", op, bc.Type)
	}
}
