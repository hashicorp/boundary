// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package nodeenrollment

import (
	"context"
	"errors"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"google.golang.org/protobuf/proto"
)

// X25519KeyProducer is an interface that can be satisfied by an underlying type
// that produces an encryption key via X25519, along with a key identifier used
// for AAD and embedding in the wrapping data. If the ID is empty, it is simply
// unused for either purpose.
type X25519KeyProducer interface {
	X25519EncryptionKey() (string, []byte, error)
	PreviousX25519EncryptionKey() (string, []byte, error)
}

// EncryptMessage takes any proto.Message and a valid key source that implements
// X25519KeyProducer. Internally it uses an `aead` wrapper from go-kms-wrapping v2.
// No options are currently supported but in the future non-AES-GCM encryption
// types could be supported by the wrapper and chosen here.
//
// The resulting value from the wrapper is marshaled before being returned.
//
// Supported options: WithRandomReader
func EncryptMessage(ctx context.Context, msg proto.Message, keySource X25519KeyProducer, opt ...Option) ([]byte, error) {
	const op = "nodeenrollment.EncryptMessage"
	switch {
	case IsNil(msg):
		return nil, fmt.Errorf("(%s) incoming message is nil", op)
	case IsNil(keySource):
		return nil, fmt.Errorf("(%s) incoming key source is nil", op)
	}

	opts, err := GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	keyId, sharedKey, err := keySource.X25519EncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving shared encryption key: %w", op, err)
	}

	aeadWrapper := aead.NewWrapper()
	if _, err := aeadWrapper.SetConfig(
		ctx,
		wrapping.WithKeyId(keyId),
		aead.WithKey(sharedKey),
		aead.WithRandomReader(opts.WithRandomReader),
	); err != nil {
		return nil, fmt.Errorf("(%s) error instantiating aead wrapper: %w", op, err)
	}

	marshaledMsg, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling incoming message: %w", op, err)
	}

	var aadOpt wrapping.Option
	if keyId != "" {
		aadOpt = wrapping.WithAad([]byte(keyId))
	}
	blobInfo, err := aeadWrapper.Encrypt(ctx, marshaledMsg, aadOpt)
	if err != nil {
		return nil, fmt.Errorf("(%s) error encrypting marshaled message: %w", op, err)
	}

	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling blob info: %w", op, err)
	}

	return marshaledBlob, nil
}

// DecryptMessage takes any a value encrypted with EncryptMessage and a valid
// key source that implements X25519KeyProducer and decrypts the message into the
// given proto.Message. Internally it uses an `aead` wrapper from
// go-kms-wrapping v2. No options are currently supported but in the future
// non-AES-GCM decryption types could be supported by the wrapper and chosen
// here.
//
// ID should match what was passed into the encryption function. It is also
// passed as additional authenticated data to the decryption function, if
// supported.
//
// If decryption fails with the current key, and a prior key is present,
// use that to try and decrypt the message in the case an older key
// was used to encrypt the incoming message
func DecryptMessage(ctx context.Context, ct []byte, keySource X25519KeyProducer, result proto.Message, _ ...Option) error {
	const op = "nodeenrollment.DecryptMessage"
	switch {
	case len(ct) == 0:
		return fmt.Errorf("(%s) incoming ciphertext is empty", op)
	case IsNil(keySource):
		return fmt.Errorf("(%s) incoming key source is nil", op)
	case IsNil(result):
		return fmt.Errorf("(%s) incoming result message is nil", op)
	}

	keyId, sharedKey, err := keySource.X25519EncryptionKey()
	if err != nil {
		return fmt.Errorf("(%s) error deriving shared encryption key: %w", op, err)
	}

	err = decryptWithKey(ctx, keyId, ct, sharedKey, result)

	// If decryption fails with the current key, try with the previous key, if present
	if err != nil {
		prevId, previousKey, prevErr := keySource.PreviousX25519EncryptionKey()
		if prevErr != nil || previousKey == nil {
			return err
		}
		prevErr = decryptWithKey(ctx, prevId, ct, previousKey, result)
		if prevErr != nil {
			err = errors.Join(err, fmt.Errorf("(%s) error decrypting with previous key: %w", op, prevErr))
			return err
		}
	}

	return nil
}

func decryptWithKey(ctx context.Context, keyId string, ct []byte, sharedKey []byte, result proto.Message) error {
	const op = "nodeenrollment.decryptWithKey"

	aeadWrapper := aead.NewWrapper()
	if _, err := aeadWrapper.SetConfig(
		ctx,
		wrapping.WithKeyId(keyId),
		aead.WithKey(sharedKey),
	); err != nil {
		return fmt.Errorf("(%s) error instantiating aead wrapper: %w", op, err)
	}

	blobInfo := new(wrapping.BlobInfo)
	if err := proto.Unmarshal(ct, blobInfo); err != nil {
		return fmt.Errorf("(%s) error unmarshaling incoming blob info: %w", op, err)
	}

	var aadOpt wrapping.Option
	if keyId != "" {
		aadOpt = wrapping.WithAad([]byte(keyId))
	}
	pt, err := aeadWrapper.Decrypt(ctx, blobInfo, aadOpt)
	if err != nil {
		return fmt.Errorf("(%s) error decrypting blob info: %w", op, err)
	}

	if err := proto.Unmarshal(pt, result); err != nil {
		return fmt.Errorf("(%s) error unmarshaling message into result: %w", op, err)
	}

	return nil
}
