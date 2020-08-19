package recovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"google.golang.org/protobuf/proto"
)

// Info is the struct required to be marshaled to be used as a token
// for the recovery workflow.
type Info struct {
	Nonce        string    `json:"nonce"`
	CreationTime time.Time `json:"creation_time"`
}

func GenerateRecoveryToken(ctx context.Context, wrapper wrapping.Wrapper) (string, error) {
	b, err := uuid.GenerateRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes for recovery token nonce: %w", err)
	}
	info := &Info{
		Nonce:        base64.RawStdEncoding.EncodeToString(b),
		CreationTime: time.Now(),
	}

	marshaledInfo, err := json.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("error marshaling recovery info: %w", err)
	}

	blobInfo, err := wrapper.Encrypt(ctx, marshaledInfo, nil)
	if err != nil {
		return "", fmt.Errorf("error encrypting recovery info: %w", err)
	}

	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", fmt.Errorf("error marshaling encrypted blob: %w", err)
	}

	return fmt.Sprintf("r_%s", base64.RawStdEncoding.EncodeToString(marshaledBlob)), nil
}

func ParseRecoveryToken(ctx context.Context, token string, wrapper wrapping.Wrapper) (*Info, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("empty token")
	}
	if !strings.HasPrefix(token, "r_") {
		return nil, errors.New("token has wrong format")
	}
	token = strings.TrimPrefix(token, "r_")

	marshaledBlob, err := base64.RawStdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("error base64-decoding token: %w", err)
	}

	blobInfo := new(wrapping.EncryptedBlobInfo)
	if err := proto.Unmarshal(marshaledBlob, blobInfo); err != nil {
		return nil, fmt.Errorf("error decoding encrypted blob: %w", err)
	}

	marshaledInfo, err := wrapper.Decrypt(ctx, blobInfo, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting recovery info: %w", err)
	}

	info := new(Info)
	if err := json.Unmarshal(marshaledInfo, info); err != nil {
		return nil, fmt.Errorf("error unmarshaling recovery info: %w", err)
	}

	return info, nil
}
