package oplog

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

const (
	// NonceSize for gcm
	NonceSize = 12
)

// Cipherable defines the required oplog crypto services
type Cipherable interface {
	Encrypt(data []byte) (encrypted []byte, err error)
	Decrypt(data []byte) (decrypted []byte, err error)
	HMAC(data []byte) (hmac []byte, err error)
	Verify(hmac []byte, data []byte) (bool, error)
}

var _ Cipherable = (*OplogCipher)(nil)

// OplogCipher defines and internal service that implements the CryptoService interface
type OplogCipher struct {
	Secret []byte
}

// HMAC the data
func (c OplogCipher) HMAC(data []byte) ([]byte, error) {
	h := hmac.New(sha256.New, []byte(c.Secret))
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Verify the hmac of the data
func (c OplogCipher) Verify(hmac []byte, data []byte) (bool, error) {
	h, err := c.HMAC(data)
	if err != nil {
		return false, err
	}
	if bytes.Equal(h, hmac) {
		return true, nil
	}
	return false, nil
}

// Encrypt the data (AES-GCM)
func (c OplogCipher) Encrypt(data []byte) ([]byte, error) {
	if len(c.Secret) != 32 {
		return nil, fmt.Errorf("key is not 32 bytes: %d", len(c.Secret))
	}
	b, err := aes.NewCipher(c.Secret)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	n := make([]byte, NonceSize)
	_, err = io.ReadFull(rand.Reader, n[:])
	if err != nil {
		return nil, err
	}
	buf := make([]byte, NonceSize)
	_ = copy(buf, n)
	buf = gcm.Seal(buf, n, data, nil)
	return buf, nil
}

// Decrypt the data (AES-GCM)
func (c OplogCipher) Decrypt(data []byte) ([]byte, error) {
	if len(c.Secret) != 32 {
		return nil, fmt.Errorf("key is not 32 bytes: %d", len(c.Secret))
	}
	b, err := aes.NewCipher(c.Secret)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	n := make([]byte, NonceSize)
	copy(n, data[:NonceSize])

	buf, err := gcm.Open(nil, n, data[NonceSize:], nil)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
