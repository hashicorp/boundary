// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr"
	pssh "github.com/hashicorp/boundary/internal/bsr/gen/ssh/v1"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	gssh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const X11RequestType = "x11"

// X11Request is a chunk to contain data for an SSH X11 request
type X11Request struct {
	*bsr.BaseChunk
	*pssh.X11Request
}

// MarshalData serializes an X11Request chunk
func (r *X11Request) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(X11Request).MarshalData"
	dataBytes, err := proto.Marshal(r.X11Request)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewX11Request creates an X11Request chunk
func NewX11Request(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*X11Request, error) {
	const op = "ssh.NewX11Request"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != X11RequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, X11RequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, X11ReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval x11Sigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &X11Request{
		BaseChunk: baseChunk,
		X11Request: &pssh.X11Request{
			RequestType:       r.Type,
			SenderChannel:     sigval.SenderChannel,
			InitialWindowSize: sigval.InitialWindowSize,
			MaximumPacketSize: sigval.MaximumPacketSize,
			OriginatorAddress: sigval.OriginatorAddress,
			OriginatorPort:    sigval.OriginatorPort,
		},
	}
	return reqData, nil
}

type x11Sigval struct {
	SenderChannel     uint32
	InitialWindowSize uint32
	MaximumPacketSize uint32
	OriginatorAddress string
	OriginatorPort    uint32
}
