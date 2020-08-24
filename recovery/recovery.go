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
	"github.com/hashicorp/shared-secure-libs/configutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"google.golang.org/protobuf/proto"
)

const nonceLength = 32

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

func GetWrapper(ctx context.Context, path string) (wrapping.Wrapper, error) {
	kmses, err := configutil.LoadConfigKMSes(path)
	if err != nil {
		return nil, fmt.Errorf("Error parsing config file: %w", err)
	}

	var kms *configutil.KMS
	for _, v := range kmses {
		if strutil.StrListContains(v.Purpose, "recovery") {
			if kms != nil {
				return nil, fmt.Errorf("Only one %q block marked for %q purpose is allowed", "kms", "recovery")
			}
			kms = v
		}
	}
	if kms == nil {
		return nil, fmt.Errorf("No %q block marked for %q purpose is allowed", "kms", "recovery")
	}

	wrapper, err := configutil.ConfigureWrapper(kms, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error configuring kms: %w", err)
	}

	return wrapper, nil
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

func ParseRecoveryToken(ctx context.Context, wrapper wrapping.Wrapper, token string) (*Info, error) {
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
