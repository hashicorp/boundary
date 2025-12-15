// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialstores

import (
	"context"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
)

// extractClientCertAndPk takes the values passed into the api for client
// certificate and client certificate key and parses them into pem blocks.
// Any non certificate pem blocks are treated as a private key. An error is
// returned if there is more than 1 private key provided across both fields.
func extractClientCertAndPk(ctx context.Context, cert, pk string) ([]*pem.Block, *pem.Block, error) {
	const op = "credentialstores.extractClientCertAndPk"
	pks, err := decodePemBlocks(ctx, pk)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to parse client certificate private key"))
	}
	var pkPem *pem.Block
	switch len(pks) {
	case 0:
	case 1:
		pkPem = pks[0]
	default:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "private key payload contained multiple pem blocks")
	}

	bs, err := decodePemBlocks(ctx, cert)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to parse client certificate into pem blocks"))
	}
	pkIdx := -1
	for i, b := range bs {
		if !strings.Contains(b.Type, "CERTIFICATE") {
			switch {
			case pkPem == nil:
				pkIdx, pkPem = i, b
			case pkIdx < 0:
				return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "client certificate contains a private key when one was also provided separately")
			default:
				return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("second primary key found at %d after previous one found at %d", i, pkIdx))
			}
		}
	}
	if pkIdx >= 0 {
		bs = append(bs[:pkIdx], bs[pkIdx+1:]...)
	}
	return bs, pkPem, nil
}

func decodePemBlocks(ctx context.Context, input string) ([]*pem.Block, error) {
	const op = "credentialstores.decodePemBlocks"
	cpIn := make([]byte, len(input))
	copy(cpIn, input)
	var p *pem.Block
	var ret []*pem.Block
	for {
		p, cpIn = pem.Decode(cpIn)
		if p == nil {
			break
		}
		ret = append(ret, p)
	}
	if len(cpIn) > 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "not all data parseable by pem block")
	}
	return ret, nil
}
