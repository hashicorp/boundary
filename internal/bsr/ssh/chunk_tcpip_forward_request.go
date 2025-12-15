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

const TCPIPForwardRequestType = "tcpip-forward"

// TCPIPForwardRequest is a chunk to contain data for an SSH TCPIP Forward request
type TCPIPForwardRequest struct {
	*bsr.BaseChunk
	*pssh.TCPIPForwardRequest
}

// MarshalData serializes an TCPIPForwardRequest chunk
func (r *TCPIPForwardRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(TCPIPForwardRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.TCPIPForwardRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewTCPIPForwardRequest creates an TCPIPForwardRequest chunk
func NewTCPIPForwardRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*TCPIPForwardRequest, error) {
	const op = "ssh.NewTCPIPForwardRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != TCPIPForwardRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, TCPIPForwardRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, TCPIPForwardReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval tCPIPForwardSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &TCPIPForwardRequest{
		BaseChunk: baseChunk,
		TCPIPForwardRequest: &pssh.TCPIPForwardRequest{
			RequestType:   r.Type,
			WantReply:     r.WantReply,
			AddressToBind: sigval.AddressToBind,
			PortToBind:    sigval.PortToBind,
		},
	}
	return reqData, nil
}

type tCPIPForwardSigval struct {
	AddressToBind string
	PortToBind    uint32
}
