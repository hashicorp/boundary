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

const XonXoffRequestType = "xon-xoff"

// XonXoffRequest is a chunk to contain data for an SSH Xon Xoff request
type XonXoffRequest struct {
	*bsr.BaseChunk
	*pssh.XonXoffRequest
}

// MarshalData serializes an XonXoffRequest chunk
func (r *XonXoffRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(XonXoffRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.XonXoffRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewXonXoffRequest creates an XonXoffRequest chunk
func NewXonXoffRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*XonXoffRequest, error) {
	const op = "ssh.NewXonXoffRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != XonXoffRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, XonXoffRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, XonXoffReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval xonXoffSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &XonXoffRequest{
		BaseChunk: baseChunk,
		XonXoffRequest: &pssh.XonXoffRequest{
			RequestType: r.Type,
			WantReply:   r.WantReply,
			ClientCanDo: sigval.ClientCanDo,
		},
	}
	return reqData, nil
}

type xonXoffSigval struct {
	ClientCanDo bool
}
