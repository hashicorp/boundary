// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package recovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

const (
	nonceLength = 32
	v1String    = "1"
)

// FutureLeeway indicates how far in the future we should allow the creation
// time of the token to be, in order to account for clock drift
var FutureLeeway = time.Minute

// Info is the struct required to be marshaled to be used as a token
// for the recovery workflow.
type Info struct {
	Nonce        string    `json:"nonce"`
	NonceBytes   []byte    `json:"-"`
	CreationTime time.Time `json:"creation_time"`
}

func GenerateRecoveryToken(ctx context.Context, wrapper wrapping.Wrapper) (string, error) {
	b, err := uuid.GenerateRandomBytes(nonceLength)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes for recovery token nonce: %w", err)
	}
	info := &Info{
		Nonce:        base64.RawStdEncoding.EncodeToString(b),
		CreationTime: time.Now(),
	}

	return formatToken(ctx, wrapper, info)
}

func formatToken(ctx context.Context, wrapper wrapping.Wrapper, info *Info) (string, error) {
	marshaledInfo, err := json.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("error marshaling recovery info: %w", err)
	}

	blobInfo, err := wrapper.Encrypt(ctx, marshaledInfo)
	if err != nil {
		return "", fmt.Errorf("error encrypting recovery info: %w", err)
	}

	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", fmt.Errorf("error marshaling encrypted blob: %w", err)
	}

	encodedMarshaledBlob := base58.FastBase58Encoding(marshaledBlob)

	return fmt.Sprintf("r_%s%s", v1String, encodedMarshaledBlob), nil
}

func ParseRecoveryToken(ctx context.Context, wrapper wrapping.Wrapper, versionedToken string) (*Info, error) {
	versionedToken = strings.TrimSpace(versionedToken)
	if versionedToken == "" {
		return nil, errors.New("empty token")
	}
	if !strings.HasPrefix(versionedToken, "r_") {
		return nil, errors.New("token has wrong format")
	}
	versionedToken = strings.TrimPrefix(versionedToken, "r_")

	ver, token := versionedToken[0:1], versionedToken[1:]

	// Don't do anything yet, but if we ever need to adjust data based on
	// version we'd do it here
	switch ver {
	case v1String:
	default:
		return nil, fmt.Errorf("unknown recovery token version %s", ver)
	}

	marshaledBlob, err := base58.FastBase58Decoding(token)
	if err != nil {
		return nil, fmt.Errorf("error base58-decoding token: %w", err)
	}
	if len(marshaledBlob) == 0 {
		return nil, fmt.Errorf("length zero after base58-decoding token")
	}

	blobInfo := new(wrapping.BlobInfo)
	if err := proto.Unmarshal(marshaledBlob, blobInfo); err != nil {
		return nil, fmt.Errorf("error decoding encrypted blob: %w", err)
	}

	marshaledInfo, err := wrapper.Decrypt(ctx, blobInfo)
	if err != nil {
		return nil, fmt.Errorf("error decrypting recovery info: %w", err)
	}

	info := new(Info)
	if err := json.Unmarshal(marshaledInfo, info); err != nil {
		return nil, fmt.Errorf("error unmarshaling recovery info: %w", err)
	}

	info.NonceBytes, err = base64.RawStdEncoding.DecodeString(info.Nonce)
	if err != nil {
		return nil, fmt.Errorf("error decoding nonce bytes: %w", err)
	}
	if len(info.NonceBytes) != nonceLength {
		return nil, errors.New("nonce has incorrect length, must be 32 bytes")
	}

	if info.CreationTime.IsZero() {
		return nil, errors.New("recovery token creation time is zero")
	}
	// It must be before the current time. This means someone can't create
	// one way in the future and keep using it. We fudge this by 1 minute to
	// account for time discrepancies between systems.
	if info.CreationTime.After(time.Now().Add(FutureLeeway)) {
		return nil, errors.New("recovery token creation time is invalid")
	}

	return info, nil
}
