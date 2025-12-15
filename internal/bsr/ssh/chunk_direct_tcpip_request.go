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

const DirectTCPIPRequestType = "direct-tcpip"

// DirectTCPIPRequest is a chunk to contain data for an SSH Direct TCPIP request
type DirectTCPIPRequest struct {
	*bsr.BaseChunk
	*pssh.DirectTCPIPRequest
}

// MarshalData serializes a DirectTCPIPRequest chunk
func (r *DirectTCPIPRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(DirectTCPIPRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.DirectTCPIPRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewDirectTCPIPRequest creates a DirectTCPIPRequest chunk
func NewDirectTCPIPRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*DirectTCPIPRequest, error) {
	const op = "ssh.NewDirectTCPIPRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != DirectTCPIPRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, DirectTCPIPRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, DirectTCPIPReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval directTCPIPSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &DirectTCPIPRequest{
		BaseChunk: baseChunk,
		DirectTCPIPRequest: &pssh.DirectTCPIPRequest{
			RequestType:         r.Type,
			SenderChannel:       sigval.SenderChannel,
			InitialWindowSize:   sigval.InitialWindowSize,
			MaximumPacketSize:   sigval.MaximumPacketSize,
			Host:                sigval.Host,
			Port:                sigval.Port,
			OriginatorIpAddress: sigval.OriginatorIpAddress,
			OriginatorPort:      sigval.OriginatorPort,
		},
	}
	return reqData, nil
}

type directTCPIPSigval struct {
	SenderChannel       uint32
	InitialWindowSize   uint32
	MaximumPacketSize   uint32
	Host                string
	Port                uint32
	OriginatorIpAddress string
	OriginatorPort      uint32
}
