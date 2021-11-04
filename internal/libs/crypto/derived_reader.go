package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/go-kms-wrapping/wrappers/multiwrapper"
	"golang.org/x/crypto/hkdf"
)

// DerivedReader returns a reader from which keys can be read, using the
// given wrapper, reader length limit, salt and context info. Salt and info can
// be nil.
//
// Example:
//	reader, _ := NewDerivedReader(wrapper, userId, jobId)
// 	key := ed25519.GenerateKey(reader)
func NewDerivedReader(wrapper wrapping.Wrapper, lenLimit int64, salt, info []byte) (*io.LimitedReader, error) {
	const op = "crypto.NewDerivedReader"
	if wrapper == nil {
		return nil, fmt.Errorf("%s: missing wrapper: %w", op, ErrInvalidParameter)
	}
	if lenLimit < 20 {
		return nil, fmt.Errorf("%s: lenLimit must be >= 20: %w", op, ErrInvalidParameter)
	}
	var aeadWrapper *aead.Wrapper
	switch w := wrapper.(type) {
	case *multiwrapper.MultiWrapper:
		raw := w.WrapperForKeyID("__base__")
		var ok bool
		if aeadWrapper, ok = raw.(*aead.Wrapper); !ok {
			return nil, fmt.Errorf("%s: unexpected wrapper type from multiwrapper base: %w", op, ErrInvalidParameter)
		}
	case *aead.Wrapper:
		if w.GetKeyBytes() == nil {
			return nil, fmt.Errorf("%s: aead wrapper missing bytes: %w", op, ErrInvalidParameter)
		}
		aeadWrapper = w
	default:
		return nil, fmt.Errorf("%s: unknown wrapper type: %w", op, ErrInvalidParameter)
	}
	reader := hkdf.New(sha256.New, aeadWrapper.GetKeyBytes(), salt, info)
	return &io.LimitedReader{
		R: reader,
		N: lenLimit,
	}, nil
}
