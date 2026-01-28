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

const SessionRequestType = "session"

// SessionRequest is a chunk to contain data for an SSH Session request
type SessionRequest struct {
	*bsr.BaseChunk
	*pssh.SessionRequest
}

// MarshalData serializes an SessionRequest chunk
func (r *SessionRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(SessionRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.SessionRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewSessionRequest creates an SessionRequest chunk
func NewSessionRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*SessionRequest, error) {
	const op = "ssh.NewSessionRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != SessionRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, SessionRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, SessionReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval sessionSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &SessionRequest{
		BaseChunk: baseChunk,
		SessionRequest: &pssh.SessionRequest{
			RequestType:       r.Type,
			SenderChannel:     sigval.SenderChannel,
			InitialWindowSize: sigval.InitialWindowSize,
			MaximumPacketSize: sigval.MaximumPacketSize,
		},
	}
	return reqData, nil
}

type sessionSigval struct {
	SenderChannel     uint32
	InitialWindowSize uint32
	MaximumPacketSize uint32
}
