package session

import (
	"crypto/ed25519"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
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

	reader, err := kms.NewDerivedReader(wrapper, 32, uId, jId)
	if err != nil {
		return nil, nil, errors.WrapDeprecated(err, op)
	}
	return ed25519.GenerateKey(reader)
}
