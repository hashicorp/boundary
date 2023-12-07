// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package bsr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/bsr/internal/checksum"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"github.com/hashicorp/boundary/internal/bsr/internal/journal"
	"github.com/hashicorp/boundary/internal/bsr/internal/sign"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/crypto"
	"google.golang.org/protobuf/proto"
)

const (
	metaFileNameTemplate    = "%s-recording.meta"
	summaryFileNameTemplate = "%s-recording-summary.json"
	checksumFileName        = "SHA256SUM"
	sigFileName             = "SHA256SUM.sig"
	journalFileName         = ".journal"
)

// ContainerType defines the type of container.
type containerType string

// Valid container types.
const (
	sessionContainer    containerType = "session"
	connectionContainer containerType = "connection"
	channelContainer    containerType = "channel"
)

// container contains a group of files in a BSR.
// Each container has corresponding .meta, .summary, SHA256SUM, and SHA256SUM.sig files.
type container struct {
	container storage.Container

	// Fields primarily used for writing
	journal    *journal.Journal
	sumName    string
	meta       *checksum.File
	sum        *checksum.File
	sumEncoder *json.Encoder
	checksums  *sign.File
	sigs       storage.File

	// Field used for reading
	shaSums  checksum.Sha256Sums
	metaFile storage.File

	// Field used for reading and writing
	keys     *kms.Keys
	metaName string
}

// newContainer creates a container for the given type backed by the provide storage.Container.
func newContainer(ctx context.Context, t containerType, c storage.Container, keys *kms.Keys) (*container, error) {
	j, err := c.OpenFile(ctx, journalFileName,
		storage.WithCreateFile(),
		storage.WithFileAccessMode(storage.WriteOnly),
		storage.WithCloseSyncMode(storage.NoSync))
	if err != nil {
		return nil, err
	}
	jj, err := journal.New(ctx, j)
	if err != nil {
		return nil, err
	}
	cc := &container{
		container: c,
		journal:   jj,
		keys:      keys,
	}

	cc.sigs, err = cc.create(ctx, sigFileName)
	if err != nil {
		return nil, err
	}

	cs, err := cc.create(ctx, checksumFileName)
	if err != nil {
		return nil, err
	}
	cc.checksums, err = sign.NewFile(ctx, cs, cc.sigs, keys)
	if err != nil {
		return nil, err
	}

	cc.metaName = fmt.Sprintf(metaFileNameTemplate, t)
	meta, err := cc.create(ctx, cc.metaName)
	if err != nil {
		return nil, err
	}
	cc.meta, err = checksum.NewFile(ctx, meta, cc.checksums)
	if err != nil {
		return nil, err
	}

	cc.sumName = fmt.Sprintf(summaryFileNameTemplate, t)
	sum, err := cc.create(ctx, cc.sumName)
	if err != nil {
		return nil, err
	}
	cc.sum, err = checksum.NewFile(ctx, sum, cc.checksums)
	if err != nil {
		return nil, err
	}
	cc.sumEncoder = json.NewEncoder(cc.sum)
	cc.sumEncoder.SetIndent("", "  ")

	return cc, nil
}

type populateKeyFunc func(c *container) (*kms.Keys, error)

// openContainer will set keys and load and verify the checksums for this container
func openContainer(ctx context.Context, t containerType, c storage.Container, keyGetFunc populateKeyFunc) (*container, error) {
	const op = "bsr.openContainer"
	switch {
	case t == "":
		return nil, fmt.Errorf("%s: missing container type: %w", op, ErrInvalidParameter)
	case is.Nil(c):
		return nil, fmt.Errorf("%s: missing container: %w", op, ErrInvalidParameter)
	case is.Nil(keyGetFunc):
		return nil, fmt.Errorf("%s: missing key function: %w", op, ErrInvalidParameter)
	}

	cc := &container{
		container: c,
	}

	keys, err := keyGetFunc(cc)
	if err != nil {
		return nil, err
	}
	cc.keys = keys

	err = cc.loadChecksums(ctx)
	if err != nil {
		return nil, err
	}

	// Load the meta file
	cc.metaName = fmt.Sprintf(metaFileNameTemplate, t)
	mFile, err := cc.container.OpenFile(ctx, cc.metaName)
	if err != nil {
		return nil, err
	}
	cc.metaFile = mFile

	return cc, nil
}

func (c *container) loadChecksums(ctx context.Context) (err error) {
	const op = "bsr.(container).loadChecksums"

	// Open and extract checksum signature
	checksumsSigFile, err := c.container.OpenFile(ctx, sigFileName)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := checksumsSigFile.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("%s: %w", op, closeErr))
		}
	}()

	checksumSigBytes := new(bytes.Buffer)
	_, err = checksumSigBytes.ReadFrom(checksumsSigFile)
	if err != nil {
		return err
	}

	sig := new(wrapping.SigInfo)
	err = proto.Unmarshal(checksumSigBytes.Bytes(), sig)
	if err != nil {
		return err
	}

	// Open and extract checksum file bytes
	checksumsFile, err := c.container.OpenFile(ctx, checksumFileName)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := checksumsFile.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("%s: %w", op, closeErr))
		}
	}()

	var checksumsBuffer bytes.Buffer
	cTee := io.TeeReader(checksumsFile, &checksumsBuffer)

	checksumBytes := new(bytes.Buffer)
	_, err = checksumBytes.ReadFrom(cTee)
	if err != nil {
		return err
	}

	verified, err := c.keys.VerifySignatureWithPubKey(ctx, sig, checksumBytes.Bytes())
	if err != nil {
		return err
	}
	if !verified {
		return fmt.Errorf("%s: failed to verify checksums signature: %w", op, ErrSignatureVerification)
	}

	// Load checksums
	sums, err := checksum.LoadSha256Sums(&checksumsBuffer)
	if err != nil {
		return err
	}
	c.shaSums = sums

	return nil
}

func (c *container) loadKey(ctx context.Context, keyFileName string) (k *wrapping.KeyInfo, err error) {
	keyFile, err := c.container.OpenFile(ctx, keyFileName)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := keyFile.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	keyBytes := new(bytes.Buffer)
	_, err = keyBytes.ReadFrom(keyFile)
	if err != nil {
		return nil, err
	}

	key := new(wrapping.KeyInfo)
	err = proto.Unmarshal(keyBytes.Bytes(), key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (c *container) loadSignature(ctx context.Context, sigFileName string) (s *wrapping.SigInfo, err error) {
	sigFile, err := c.container.OpenFile(ctx, sigFileName)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := sigFile.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	sigBytes := new(bytes.Buffer)
	_, err = sigBytes.ReadFrom(sigFile)
	if err != nil {
		return nil, err
	}

	signature := new(wrapping.SigInfo)
	err = proto.Unmarshal(sigBytes.Bytes(), signature)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// loadKeys will load the BSR keys from storage, unmarshal and unwrap them.
// After unwrapping, it will verify the key signature files before setting the keys
// on the container
func (c *container) loadKeys(ctx context.Context, keyUnwrapFn kms.KeyUnwrapCallbackFunc) (*kms.Keys, error) {
	const op = "bsr.(container).loadKeys"

	switch {
	case keyUnwrapFn == nil:
		return nil, fmt.Errorf("%s: missing key unwrap function: %w", op, ErrInvalidParameter)
	}

	bsrPubKey, err := c.loadKey(ctx, bsrPubKeyFileName)
	if err != nil {
		return nil, err
	}

	wrappedBsrKey, err := c.loadKey(ctx, wrappedBsrKeyFileName)
	if err != nil {
		return nil, err
	}

	wrappedPrivKey, err := c.loadKey(ctx, wrappedPrivKeyFileName)
	if err != nil {
		return nil, err
	}

	pubKeyBsrSignature, err := c.loadSignature(ctx, pubKeyBsrSignatureFileName)
	if err != nil {
		return nil, err
	}

	pubKeySelfSignature, err := c.loadSignature(ctx, pubKeySelfSignatureFileName)
	if err != nil {
		return nil, err
	}

	unwrappedKeys, err := keyUnwrapFn(kms.WrappedKeys{
		WrappedBsrKey:  wrappedBsrKey,
		WrappedPrivKey: wrappedPrivKey,
	})
	if err != nil {
		return nil, err
	}

	keys := &kms.Keys{
		PubKey:              bsrPubKey,
		BsrKey:              unwrappedKeys.BsrKey,
		PrivKey:             unwrappedKeys.PrivKey,
		PubKeyBsrSignature:  pubKeyBsrSignature,
		PubKeySelfSignature: pubKeySelfSignature,
	}

	verified, err := keys.VerifyPubKeySelfSignature(ctx)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, fmt.Errorf("%s: failed to verify public self signed key: %w", op, ErrSignatureVerification)
	}

	verified, err = keys.VerifyPubKeyBsrSignature(ctx)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, fmt.Errorf("%s: failed to verify pub key signature: %w", op, ErrSignatureVerification)
	}

	return keys, nil
}

func (c *container) verifyMetadata(ctx context.Context, sha256Reader *crypto.Sha256SumReader) error {
	const op = "bsr.(container).verifyMetadata"
	metaSum, err := sha256Reader.Sum(ctx, crypto.WithHexEncoding(true))
	if err != nil {
		return err
	}
	expectedMetaSum, err := c.shaSums.Sum(c.metaName)
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedMetaSum, metaSum) {
		return fmt.Errorf("%s: meta checksum did not match expected value", op)
	}
	return nil
}

// create creates a new file in the container for writing.
func (c *container) create(ctx context.Context, s string, options ...storage.Option) (storage.File, error) {
	const op = "bsr.(container).create"

	err := c.journal.Record("CREATING", s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	var f storage.File
	switch len(options) {
	case 0:
		f, err = c.container.Create(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	default:
		f, err = c.container.OpenFile(ctx, s, options...)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	jf, err := journal.NewFile(ctx, f, c.journal)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer c.journal.Record("CREATED", s)
	return jf, nil
}

func (c *container) decodeJsonFile(ctx context.Context, s string, v any) error {
	const op = "bsr.(container).decodeJsonFile"

	return c.decodeFile(ctx, s, func(_ context.Context, r io.Reader) error {
		dec := json.NewDecoder(r)
		if err := dec.Decode(v); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		return nil
	})
}

func (c *container) decodeFile(ctx context.Context, s string, fn func(context.Context, io.Reader) error) error {
	const op = "bsr.(container).decodeFile"

	expectedSum, err := c.shaSums.Sum(s)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	f, err := c.container.OpenFile(ctx, s)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	sha256Reader, err := crypto.NewSha256SumReader(ctx, f)
	if err != nil {
		f.Close()
		return fmt.Errorf("%s: %w", op, err)
	}
	defer sha256Reader.Close()

	if err := fn(ctx, sha256Reader); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	gotSum, err := sha256Reader.Sum(ctx, crypto.WithHexEncoding(true))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if !bytes.Equal(expectedSum, gotSum) {
		return fmt.Errorf("%s: checksum did not match expected value", op)
	}

	return nil
}

// syncBsrKey will take the marshalled bytes of a key, write its contents to a local file,
// and then close it. The key file is created using the synchronous storage option, so
// close will block until the file is synced to remote storage
func (c *container) syncBsrKey(ctx context.Context, s string, data []byte) error {
	const op = "bsr.(container).syncBsrKey"
	switch {
	case len(s) == 0:
		return fmt.Errorf("%s: missing file name %w", op, ErrInvalidParameter)
	case data == nil:
		return fmt.Errorf("%s: missing data payload %w", op, ErrInvalidParameter)
	}

	jf, err := c.create(ctx, s, storage.WithCreateFile(),
		storage.WithFileAccessMode(storage.WriteOnly),
		storage.WithCloseSyncMode(storage.Synchronous))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	cf, err := checksum.NewFile(ctx, jf, c.checksums)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = cf.Write(data)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	err = cf.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// writeMetaString writes a string to the containers meta file.
func (c *container) writeMetaString(_ context.Context, s string) (int, error) {
	return c.meta.WriteString(s)
}

// writeMetaLine writes a new line terminated line to the container's meta file.
func (c *container) writeMetaLine(_ context.Context, s string) (int, error) {
	return c.meta.WriteString(s + "\n")
}

// WriteMeta writes a new line terminated key : value pair to the container's meta file
func (c *container) WriteMeta(_ context.Context, k, v string) (int, error) {
	return c.meta.WriteString(fmt.Sprintf("%s: %s\n", k, v))
}

// EncodeSummary writes a new line terminated key : value pair to the container's summary file
func (c *container) EncodeSummary(_ context.Context, s any) error {
	return c.sumEncoder.Encode(s)
}

// WriteBinaryChecksum writes a checksum for a binary file to the checksum file.
func (c *container) WriteBinaryChecksum(_ context.Context, sum []byte, fname string) (int, error) {
	return c.checksums.WriteString(fmt.Sprintf("%x *%s\n", sum, fname))
}

// close closes a container, closing the underlying files in a container.
func (c *container) close(_ context.Context) error {
	const op = "bsr.(container).close"

	var closeError error

	if !is.Nil(c.meta) {
		if err := c.meta.Close(); err != nil {
			closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
		}
	}

	if !is.Nil(c.sum) {
		if err := c.sum.Close(); err != nil {
			closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
		}
	}

	if !is.Nil(c.checksums) {
		if err := c.checksums.Close(); err != nil {
			closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
		}
	}

	if !is.Nil(c.sigs) {
		if err := c.sigs.Close(); err != nil {
			closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
		}
	}

	if !is.Nil(c.journal) {
		if err := c.journal.Close(); err != nil {
			closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
		}
	}

	if !is.Nil(c.container) {
		if err := c.container.Close(); err != nil {
			closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
		}
	}

	return closeError
}
