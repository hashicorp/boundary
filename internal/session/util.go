package session

import (
	"crypto/ed25519"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// DeriveED25519Key generates a key based on the scope's session DEK, the
// requesting user, and the generated job ID.
func DeriveED25519Key(wrapper wrapping.Wrapper, userId, jobId string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	const op = "session.DeriveED25519Key"
	var uId, jId []byte
	if userId != "" {
		uId = []byte(userId)
	}
	if jobId != "" {
		jId = []byte(jobId)
	}
	if wrapper == nil {
		return nil, nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing wrapper")
	}

	reader, err := crypto.NewDerivedReader(wrapper, 32, uId, jId)
	if err != nil {
		return nil, nil, errors.WrapDeprecated(err, op)
	}
	return ed25519.GenerateKey(reader)
}
