// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/bsr/internal/checksum"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/crypto"
	"google.golang.org/protobuf/proto"
)

const (
	bsrFileNameTemplate        = "%s.bsr"
	connectionFileNameTemplate = "%s.connection"
	channelFileNameTemplate    = "%s.channel"
	messagesFileNameTemplate   = "messages-%s.data"
	requestsFileNameTemplate   = "requests-%s.data"
	sessionMetaFileName        = "session-meta.json"

	bsrPubKeyFileName           = "bsrKey.pub"
	wrappedBsrKeyFileName       = "wrappedBsrKey"
	wrappedPrivKeyFileName      = "wrappedPrivKey"
	pubKeyBsrSignatureFileName  = "pubKeyBsrSignature.sign"
	pubKeySelfSignatureFileName = "pubKeySelfSignature.sign"
)

// Session is the top level container in a bsr that contains the files for
// a recorded session.
type Session struct {
	*container
	multiplexed bool

	Meta        *SessionRecordingMeta
	SessionMeta *SessionMeta
}

// NewSession creates a Session container for a given session id.
func NewSession(ctx context.Context, meta *SessionRecordingMeta, sessionMeta *SessionMeta, f storage.FS, keys *kms.Keys, options ...Option) (*Session, error) {
	const op = "bsr.NewSession"

	switch {
	case is.Nil(meta):
		return nil, fmt.Errorf("%s: missing meta: %w", op, ErrInvalidParameter)
	case is.Nil(sessionMeta):
		return nil, fmt.Errorf("%s: missing session meta: %w", op, ErrInvalidParameter)
	case meta.Id == "":
		return nil, fmt.Errorf("%s: missing session id: %w", op, ErrInvalidParameter)
	case !is.Nil(sessionMeta.StaticHost) && !is.Nil(sessionMeta.DynamicHost):
		return nil, fmt.Errorf("%s: sessionMeta cannot contain both static and dynamic host information: %w", op, ErrInvalidParameter)
	case len(sessionMeta.StaticJSONCredentials) == 0 &&
		len(sessionMeta.StaticUsernamePasswordCredentials) == 0 &&
		len(sessionMeta.StaticSshPrivateKeyCredentials) == 0 &&
		len(sessionMeta.VaultGenericLibraries) == 0 &&
		len(sessionMeta.VaultSshCertificateLibraries) == 0:
		return nil, fmt.Errorf("%s: missing credential information: %w", op, ErrInvalidParameter)
	case is.Nil(sessionMeta.User):
		return nil, fmt.Errorf("%s: missing session user: %w", op, ErrInvalidParameter)
	case is.Nil(sessionMeta.Target):
		return nil, fmt.Errorf("%s: missing session target: %w", op, ErrInvalidParameter)
	case is.Nil(sessionMeta.Worker):
		return nil, fmt.Errorf("%s: missing session worker: %w", op, ErrInvalidParameter)
	case is.Nil(f):
		return nil, fmt.Errorf("%s: missing storage fs: %w", op, ErrInvalidParameter)
	case is.Nil(keys):
		return nil, fmt.Errorf("%s: missing kms keys: %w", op, ErrInvalidParameter)
	}

	opts := getOpts(options...)

	c, err := f.New(ctx, fmt.Sprintf(bsrFileNameTemplate, meta.Id))
	if err != nil {
		return nil, err
	}

	nc, err := newContainer(ctx, sessionContainer, c, keys)
	if err != nil {
		return nil, err
	}

	// Sync keys and signatures
	err = persistBsrSessionKeys(ctx, keys, nc)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("%s: %w", op, ErrBsrKeyPersistenceFailure))
	}

	sm, err := nc.create(ctx, sessionMetaFileName)
	if err != nil {
		return nil, err
	}
	smw, err := checksum.NewFile(ctx, sm, nc.checksums)
	if err != nil {
		return nil, err
	}
	enc := json.NewEncoder(smw)
	if err := enc.Encode(sessionMeta); err != nil {
		smw.Close()
		return nil, err
	}
	if err := smw.Close(); err != nil {
		return nil, err
	}

	err = meta.writeMeta(ctx, nc)
	if err != nil {
		return nil, err
	}

	return &Session{
		container:   nc,
		multiplexed: opts.withSupportsMultiplex,
		Meta:        meta,
		SessionMeta: sessionMeta,
	}, nil
}

// persistBsrSessionKeys will marshal, write, and close BSR keys locally before syncing to
// storage. Any error while syncing the key files should result in the termination of
// the session this recording is for.
// The key files synced are:
// * the BSR public key, bsrKey.pub
// * the wrapped BSR key, wrappedBsrKey
// * the wrapped private key, wrappedPrivKey
// * the public key BSR signature, pubKeyBsrSignature.sign
// * the public key self signature, pubKeySelfSignature.sign
func persistBsrSessionKeys(ctx context.Context, keys *kms.Keys, c *container) error {
	const op = "bsr.persistBsrSessionKeys"
	switch {
	case keys.PubKey == nil:
		return fmt.Errorf("%s: missing kms pub key: %w", op, ErrInvalidParameter)
	case keys.WrappedBsrKey == nil:
		return fmt.Errorf("%s: missing kms wrapped BSR key: %w", op, ErrInvalidParameter)
	case keys.WrappedPrivKey == nil:
		return fmt.Errorf("%s: missing kms wrapped priv key: %w", op, ErrInvalidParameter)
	case keys.PubKeyBsrSignature == nil:
		return fmt.Errorf("%s: missing kms pub key BSR signature: %w", op, ErrInvalidParameter)
	case keys.PubKeySelfSignature == nil:
		return fmt.Errorf("%s: missing kms pub key self signature: %w", op, ErrInvalidParameter)
	}

	keyFiles := map[string]proto.Message{
		bsrPubKeyFileName:           keys.PubKey,
		wrappedBsrKeyFileName:       keys.WrappedBsrKey,
		wrappedPrivKeyFileName:      keys.WrappedPrivKey,
		pubKeyBsrSignatureFileName:  keys.PubKeyBsrSignature,
		pubKeySelfSignatureFileName: keys.PubKeySelfSignature,
	}
	for f, k := range keyFiles {
		b, err := proto.Marshal(k)
		if err != nil {
			return fmt.Errorf("%s: failed to marshal data for %s: %w", op, f, err)
		}
		err = c.syncBsrKey(ctx, f, b)
		if err != nil {
			return fmt.Errorf("%s: failed syncing bsr key %s: %w", op, f, err)
		}
	}

	return nil
}

// OpenSession retrieves a BSR from storage using the sessionRecordingId and initializes it for reading.
// Encryption keys necessary for checking signed files will be unwrapped using the keyUnwrapFn
// Signature and checksum files will then be verified.
// Fields on the underlying container will be populated so that the returned Session can be used for BSR
// playback and conversion to formats such as asciinema
func OpenSession(ctx context.Context, sessionRecordingId string, f storage.FS, keyUnwrapFn kms.KeyUnwrapCallbackFunc) (*Session, error) {
	const op = "bsr.OpenSession"
	switch {
	case sessionRecordingId == "":
		return nil, fmt.Errorf("%s: missing session recording id: %w", op, ErrInvalidParameter)
	case f == nil:
		return nil, fmt.Errorf("%s: missing storage: %w", op, ErrInvalidParameter)
	case keyUnwrapFn == nil:
		return nil, fmt.Errorf("%s: missing key unwrap function: %w", op, ErrInvalidParameter)
	}

	c, err := f.Open(ctx, fmt.Sprintf(bsrFileNameTemplate, sessionRecordingId))
	if err != nil {
		return nil, err
	}

	keyPopFn := func(c *container) (*kms.Keys, error) {
		return c.loadKeys(ctx, keyUnwrapFn)
	}
	cc, err := openContainer(ctx, sessionContainer, c, keyPopFn)
	if err != nil {
		return nil, err
	}

	// Load and verify recording metadata
	sha256Reader, err := crypto.NewSha256SumReader(ctx, cc.metaFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	meta, err := decodeSessionRecordingMeta(ctx, sha256Reader)
	if err != nil {
		return nil, err
	}
	err = cc.verifyMetadata(ctx, sha256Reader)
	if err != nil {
		return nil, err
	}

	sessionMeta := &SessionMeta{}
	if err := cc.decodeJsonFile(ctx, sessionMetaFileName, sessionMeta); err != nil {
		return nil, err
	}

	session := &Session{
		container:   cc,
		Meta:        meta,
		SessionMeta: sessionMeta,
	}

	return session, nil
}

// Close closes the Session container.
func (s *Session) Close(ctx context.Context) error {
	return s.container.close(ctx)
}

// Connection is a container in a bsr for a specific connection in a session
// container. It contains the files for the recorded connection.
type Connection struct {
	*container
	multiplexed bool

	Meta *ConnectionRecordingMeta
}

// NewConnection creates a Connection container for a given connection id.
func (s *Session) NewConnection(ctx context.Context, meta *ConnectionRecordingMeta) (*Connection, error) {
	const op = "bsr.(Session).NewConnection"

	switch {
	case is.Nil(meta):
		return nil, fmt.Errorf("%s: missing connection meta: %w", op, ErrInvalidParameter)
	case meta.Id == "":
		return nil, fmt.Errorf("%s: missing connection id: %w", op, ErrInvalidParameter)
	}

	name := fmt.Sprintf(connectionFileNameTemplate, meta.Id)
	sc, err := s.container.container.SubContainer(ctx, name, storage.WithCreateFile(), storage.WithFileAccessMode(storage.WriteOnly))
	if err != nil {
		return nil, err
	}
	if _, err := s.WriteMeta(ctx, "connection", name); err != nil {
		return nil, err
	}

	nc, err := newContainer(ctx, connectionContainer, sc, s.keys)
	if err != nil {
		return nil, err
	}
	if _, err := nc.WriteMeta(ctx, "id", meta.Id); err != nil {
		return nil, err
	}
	return &Connection{
		container:   nc,
		multiplexed: s.multiplexed,
		Meta:        meta,
	}, nil
}

// OpenConnection will open and validate a BSR connection
func (s *Session) OpenConnection(ctx context.Context, connId string) (*Connection, error) {
	const op = "bsr.(Session).OpenConnection"
	switch {
	case connId == "":
		return nil, fmt.Errorf("%s: missing connection id: %w", op, ErrInvalidParameter)
	}

	name := fmt.Sprintf(connectionFileNameTemplate, connId)

	switch {
	case !s.Meta.connections[name]:
		return nil, fmt.Errorf("%s: connection id does not exist within this session: %w", op, ErrInvalidParameter)
	}

	c, err := s.container.container.SubContainer(ctx, name)
	if err != nil {
		return nil, err
	}

	keyPopFn := func(c *container) (*kms.Keys, error) {
		return s.keys, nil
	}
	cc, err := openContainer(ctx, connectionContainer, c, keyPopFn)
	if err != nil {
		return nil, err
	}

	// Load and verify connection metadata
	sha256Reader, err := crypto.NewSha256SumReader(ctx, cc.metaFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	sm, err := decodeConnectionRecordingMeta(ctx, sha256Reader)
	if err != nil {
		return nil, err
	}
	err = cc.verifyMetadata(ctx, sha256Reader)
	if err != nil {
		return nil, err
	}

	connection := &Connection{
		container: cc,
		Meta:      sm,
	}

	return connection, nil
}

// NewChannel creates a Channel container for a given channel id.
func (c *Connection) NewChannel(ctx context.Context, meta *ChannelRecordingMeta) (*Channel, error) {
	const op = "bsr.(Connection).NewChannel"

	if !c.multiplexed {
		return nil, fmt.Errorf("%s: connection cannot make channels: %w", op, ErrNotSupported)
	}

	switch {
	case is.Nil(meta):
		return nil, fmt.Errorf("%s: missing channel meta: %w", op, ErrInvalidParameter)
	case meta.Id == "":
		return nil, fmt.Errorf("%s: missing channel id: %w", op, ErrInvalidParameter)
	}

	name := fmt.Sprintf(channelFileNameTemplate, meta.Id)
	sc, err := c.container.container.SubContainer(ctx, name, storage.WithCreateFile(), storage.WithFileAccessMode(storage.WriteOnly))
	if err != nil {
		return nil, err
	}
	if _, err := c.WriteMeta(ctx, "channel", name); err != nil {
		return nil, err
	}
	nc, err := newContainer(ctx, channelContainer, sc, c.keys)
	if err != nil {
		return nil, err
	}
	if _, err := nc.WriteMeta(ctx, "id", meta.Id); err != nil {
		return nil, err
	}
	if _, err := nc.WriteMeta(ctx, "channelType", meta.Type); err != nil {
		return nil, err
	}
	return &Channel{
		container: nc,
		Meta:      meta,
	}, nil
}

// OpenChannel will open and validate a BSR channel
func (c *Connection) OpenChannel(ctx context.Context, chanId string) (*Channel, error) {
	const op = "bsr.OpenChannel"
	switch {
	case chanId == "":
		return nil, fmt.Errorf("%s: missing channel id: %w", op, ErrInvalidParameter)
	}

	name := fmt.Sprintf(channelFileNameTemplate, chanId)
	switch {
	case !c.Meta.channels[name]:
		return nil, fmt.Errorf("%s: channel id does not exist within this connection: %w", op, ErrInvalidParameter)
	}

	con, err := c.container.container.SubContainer(ctx, name)
	if err != nil {
		return nil, err
	}

	keyPopFn := func(cn *container) (*kms.Keys, error) {
		return c.keys, nil
	}
	cc, err := openContainer(ctx, channelContainer, con, keyPopFn)
	if err != nil {
		return nil, err
	}

	// Load and verify channel metadata
	sha256Reader, err := crypto.NewSha256SumReader(ctx, cc.metaFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	sm, err := decodeChannelRecordingMeta(ctx, sha256Reader)
	if err != nil {
		return nil, err
	}
	err = cc.verifyMetadata(ctx, sha256Reader)
	if err != nil {
		return nil, err
	}

	channel := &Channel{
		container: cc,
		Meta:      sm,
	}

	return channel, nil
}

// NewMessagesWriter creates a writer for recording channel messages.
func (c *Connection) NewMessagesWriter(ctx context.Context, dir Direction) (io.Writer, error) {
	const op = "bsr.(Connection).NewMessagesWriter"

	switch {
	case !ValidDirection(dir):
		return nil, fmt.Errorf("%s: invalid direction: %w", op, ErrInvalidParameter)
	}

	messagesName := fmt.Sprintf(messagesFileNameTemplate, dir.String())
	_, err := c.container.WriteMeta(ctx, "messages", dir.String())
	if err != nil {
		return nil, err
	}
	m, err := c.container.create(ctx, messagesName)
	if err != nil {
		return nil, err
	}

	return checksum.NewFile(ctx, m, c.checksums)
}

// NewRequestsWriter creates a writer for recording connection requests.
func (c *Connection) NewRequestsWriter(ctx context.Context, dir Direction) (io.Writer, error) {
	const op = "bsr.(Connection).NewRequestsWriter"

	switch {
	case !ValidDirection(dir):
		return nil, fmt.Errorf("%s: invalid direction: %w", op, ErrInvalidParameter)
	}

	requestName := fmt.Sprintf(requestsFileNameTemplate, dir.String())
	_, err := c.container.WriteMeta(ctx, "requests", dir.String())
	if err != nil {
		return nil, err
	}
	m, err := c.container.create(ctx, requestName)
	if err != nil {
		return nil, err
	}

	return checksum.NewFile(ctx, m, c.checksums)
}

// Close closes the Connection container.
func (c *Connection) Close(ctx context.Context) error {
	return c.container.close(ctx)
}

// Channel is a container in a bsr for a specific channel in a session
// container. It contains the files for the recorded channel.
type Channel struct {
	*container

	Meta *ChannelRecordingMeta
}

// Close closes the Channel container.
func (c *Channel) Close(ctx context.Context) error {
	return c.container.close(ctx)
}

// NewMessagesWriter creates a writer for recording channel messages.
func (c *Channel) NewMessagesWriter(ctx context.Context, dir Direction) (io.Writer, error) {
	const op = "bsr.(Channel).NewMessagesWriter"

	switch {
	case !ValidDirection(dir):
		return nil, fmt.Errorf("%s: invalid direction: %w", op, ErrInvalidParameter)
	}

	messagesName := fmt.Sprintf(messagesFileNameTemplate, dir.String())
	_, err := c.container.WriteMeta(ctx, "messages", dir.String())
	if err != nil {
		return nil, err
	}
	m, err := c.container.create(ctx, messagesName)
	if err != nil {
		return nil, err
	}

	return checksum.NewFile(ctx, m, c.checksums)
}

// NewRequestsWriter creates a writer for recording channel requests.
func (c *Channel) NewRequestsWriter(ctx context.Context, dir Direction) (io.Writer, error) {
	const op = "bsr.(Channel).NewRequestsWriter"

	switch {
	case !ValidDirection(dir):
		return nil, fmt.Errorf("%s: invalid direction: %w", op, ErrInvalidParameter)
	}

	requestName := fmt.Sprintf(requestsFileNameTemplate, dir.String())
	_, err := c.container.WriteMeta(ctx, "requests", dir.String())
	if err != nil {
		return nil, err
	}
	m, err := c.container.create(ctx, requestName)
	if err != nil {
		return nil, err
	}

	return checksum.NewFile(ctx, m, c.checksums)
}

// OpenMessageScanner opens a ChunkScanner for a channel's recorded messages.
func (c *Channel) OpenMessageScanner(ctx context.Context, dir Direction) (*ChunkScanner, error) {
	const op = "bsr.(Channel).OpenMessageScanner"

	messagesName := fmt.Sprintf(messagesFileNameTemplate, dir.String())
	m, err := c.container.container.OpenFile(ctx, messagesName, storage.WithFileAccessMode(storage.ReadOnly))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	expectedSum, err := c.shaSums.Sum(messagesName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return NewChunkScanner(ctx, m, WithSha256Sum(expectedSum))
}

// OpenRequestScanner opens a ChunkScanner for a channel's recorded requests.
func (c *Channel) OpenRequestScanner(ctx context.Context, dir Direction) (*ChunkScanner, error) {
	const op = "bsr.(Channel).OpenRequestScanner"

	requestName := fmt.Sprintf(requestsFileNameTemplate, dir.String())
	m, err := c.container.container.OpenFile(ctx, requestName, storage.WithFileAccessMode(storage.ReadOnly))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	expectedSum, err := c.shaSums.Sum(requestName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return NewChunkScanner(ctx, m, WithSha256Sum(expectedSum))
}
