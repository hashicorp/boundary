package session

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/go-kms-wrapping/wrappers/multiwrapper"
	"golang.org/x/crypto/hkdf"
)

// DeriveED25519Key generates a key based on the scope's session DEK, the
// requesting user, and the generated job ID.
func DeriveED25519Key(wrapper wrapping.Wrapper, userId, jobId string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	const op = "session.DeriveED25519Key"
	var aeadWrapper *aead.Wrapper
	switch w := wrapper.(type) {
	case *multiwrapper.MultiWrapper:
		raw := w.WrapperForKeyID("__base__")
		var ok bool
		if aeadWrapper, ok = raw.(*aead.Wrapper); !ok {
			return nil, nil, errors.New(errors.InvalidParameter, op, "unexpected wrapper type from multiwrapper base")
		}
	case *aead.Wrapper:
		aeadWrapper = w
	default:
		return nil, nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("unknown wrapper type %T", wrapper))
	}
	reader := hkdf.New(sha256.New, aeadWrapper.GetKeyBytes(), []byte(jobId), []byte(userId))
	limitedReader := &io.LimitedReader{
		R: reader,
		N: 32,
	}
	pub, pvt, err := ed25519.GenerateKey(limitedReader)
	if err != nil {
		return nil, nil, errors.Wrap(err, op, errors.WithCode(errors.FixMe))
	}
	return pub, pvt, nil
}
