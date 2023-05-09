// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/internal/bsr/internal/checksum"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
	"google.golang.org/protobuf/proto"
)

const (
	bsrFile        = "%s.bsr"
	connectionFile = "%s.connection"
	channelFile    = "%s.channel"
	messagesFile   = "messages-%s.data"
	requestsFile   = "requests-%s.data"

	bsrPubKeyFile           = "bsrKey.pub"
	wrappedBsrKeyFile       = "wrappedBsrKey"
	wrappedPrivKeyFile      = "wrappedPrivKey"
	pubKeyBsrSignatureFile  = "pubKeyBsrSignature.sign"
	pubKeySelfSignatureFile = "pubKeySelfSignature.sign"
)

// decodeSessionMeta will populate a SessionMeta for an opened BSR Session
// TODO Unmarshal without brute force
func decodeSessionMeta(ctx context.Context, r io.Reader) (*SessionMeta, error) {
	const op = "bsr.decodeSessionMeta"

	switch {
	case r == nil:
		return nil, fmt.Errorf("%s: missing session meta file: %w", op, ErrInvalidParameter)
	}

	s := &SessionMeta{}
	user := &User{Scope: Scope{}}
	target := &Target{Scope: Scope{}}
	sHost := &StaticHost{Catalog: StaticHostCatalog{}}
	dHost := &DynamicHost{Catalog: DynamicHostCatalog{}}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		l := scanner.Text()
		if len(l) == 0 {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return nil, fmt.Errorf("%s: session meta file contains invalid entry; expecting k: v pair:%s", op, l)
		}
		v = strings.TrimSpace(v)
		switch {
		case k == "id":
			s.Id = v
		case k == "protocol":
			s.Protocol = Protocol(v)

		// User
		case k == "user_publicId":
			user.PublicId = v
		case k == "user_name":
			user.Name = v
		case k == "user_description":
			user.Description = v
		case k == "user_scope_publicId":
			user.Scope.PublicId = v
		case k == "user_scope_name":
			user.Scope.Name = v
		case k == "user_scope_description":
			user.Scope.Description = v
		case k == "user_scope_type":
			user.Scope.Type = v
		case k == "user_scope_parentId":
			user.Scope.ParentId = v
		case k == "user_scope_primaryAuthMethod":
			user.Scope.PrimaryAuthMethodId = v

		// Target
		case k == "target_publicId":
			target.PublicId = v
		case k == "target_projectId":
			target.ProjectId = v
		case k == "target_name":
			target.Name = v
		case k == "target_description":
			target.Description = v
		case k == "target_defaultPort":
			dp, err := strconv.Atoi(v)
			if err != nil {
				return nil, err
			}
			target.DefaultPort = uint32(dp)
		case k == "target_sessionMaxSeconds":
			sms, err := strconv.Atoi(v)
			if err != nil {
				return nil, err
			}
			target.SessionMaxSeconds = uint32(sms)
		case k == "target_sessionConnectionLimit":
			scl, err := strconv.Atoi(v)
			if err != nil {
				return nil, err
			}
			target.SessionConnectionLimit = int32(scl)
		case k == "target_workerFilter":
			target.WorkerFilter = v
		case k == "target_egressWorkerFilter":
			target.EgressWorkerFilter = v
		case k == "target_ingressWorkerFilter":
			target.IngressWorkerFilter = v
		case k == "target_scope_publicId":
			target.Scope.PublicId = v
		case k == "target_scope_name":
			target.Scope.Name = v
		case k == "target_scope_description":
			target.Scope.Description = v
		case k == "target_scope_type":
			target.Scope.Type = v
		case k == "target_scope_parentId":
			target.Scope.ParentId = v
		case k == "target_scope_primaryAuthMethod":
			target.Scope.PrimaryAuthMethodId = v

		// Static Host
		case k == "staticHost_publicId":
			sHost.PublicId = v
		case k == "staticHost_name":
			sHost.Name = v
		case k == "staticHost_description":
			sHost.Description = v
		case k == "staticHost_address":
			sHost.Address = v
		case k == "staticHostCatalog_publicId":
			sHost.Catalog.PublicId = v
		case k == "staticHostCatalog_projectId":
			sHost.Catalog.ProjectId = v
		case k == "staticHostCatalog_name":
			sHost.Catalog.Name = v
		case k == "staticHostCatalog_description":
			sHost.Catalog.Description = v

		// Dynamic Host
		case k == "dynamicHost_publicId":
			dHost.PublicId = v
		case k == "dynamicHost_name":
			dHost.Name = v
		case k == "dynamicHost_description":
			dHost.Description = v
		case k == "dynamicHost_externalId":
			dHost.ExternalId = v
		case k == "dynamicHostCatalog_publicId":
			dHost.Catalog.PublicId = v
		case k == "dynamicHostCatalog_projectId":
			dHost.Catalog.ProjectId = v
		case k == "dynamicHostCatalog_name":
			dHost.Catalog.Name = v
		case k == "dynamicHostCatalog_description":
			dHost.Catalog.Description = v
		case k == "dynamicHostCatalog_pluginId":
			dHost.Catalog.PluginId = v
		case k == "dynamicHostCatalog_attributes":
			dHost.Catalog.Attributes = v
		}
	}

	s.Target = target
	s.User = user
	if sHost.PublicId != "" {
		s.StaticHost = sHost
	}
	if dHost.PublicId != "" {
		s.DynamicHost = dHost
	}

	return s, nil
}

// Session is the top level container in a bsr that contains the files for
// a recorded session.
type Session struct {
	*container
	multiplexed bool

	Meta *SessionMeta
}

// NewSession creates a Session container for a given session id.
func NewSession(ctx context.Context, meta *SessionMeta, f storage.FS, keys *kms.Keys, options ...Option) (*Session, error) {
	const op = "bsr.NewSession"

	switch {
	case is.Nil(meta):
		return nil, fmt.Errorf("%s: missing session meta: %w", op, ErrInvalidParameter)
	case meta.Id == "":
		return nil, fmt.Errorf("%s: missing session id: %w", op, ErrInvalidParameter)
	case is.Nil(meta.StaticHost) && is.Nil(meta.DynamicHost):
		return nil, fmt.Errorf("%s: missing session host information: %w", op, ErrInvalidParameter)
	case !is.Nil(meta.StaticHost) && !is.Nil(meta.DynamicHost):
		return nil, fmt.Errorf("%s: meta cannot contain both static and dynamic host information: %w", op, ErrInvalidParameter)
	case len(meta.StaticCredentialStore) == 0 && len(meta.VaultCredentialStore) == 0:
		return nil, fmt.Errorf("%s: missing credential information: %w", op, ErrInvalidParameter)
	case is.Nil(meta.User):
		return nil, fmt.Errorf("%s: missing session user: %w", op, ErrInvalidParameter)
	case is.Nil(meta.Target):
		return nil, fmt.Errorf("%s: missing session target: %w", op, ErrInvalidParameter)
	case is.Nil(meta.Worker):
		return nil, fmt.Errorf("%s: missing session worker: %w", op, ErrInvalidParameter)
	case is.Nil(f):
		return nil, fmt.Errorf("%s: missing storage fs: %w", op, ErrInvalidParameter)
	case is.Nil(keys):
		return nil, fmt.Errorf("%s: missing kms keys: %w", op, ErrInvalidParameter)
	}

	opts := getOpts(options...)

	c, err := f.New(ctx, fmt.Sprintf(bsrFile, meta.Id))
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

	err = meta.writeMeta(ctx, nc)
	if err != nil {
		return nil, err
	}

	return &Session{
		container:   nc,
		multiplexed: opts.withSupportsMultiplex,
		Meta:        meta,
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
		bsrPubKeyFile:           keys.PubKey,
		wrappedBsrKeyFile:       keys.WrappedBsrKey,
		wrappedPrivKeyFile:      keys.WrappedPrivKey,
		pubKeyBsrSignatureFile:  keys.PubKeyBsrSignature,
		pubKeySelfSignatureFile: keys.PubKeySelfSignature,
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
	panic("not implemented")
}

// ConnectionMeta contains metadata about a connection in a BSR.
type ConnectionMeta struct {
	Id string
}

func (c ConnectionMeta) isValid() bool {
	switch {
	case c.Id == "":
		return false
	default:
		return true
	}
}

// decodeConnectionMeta will populate the ConnectionMeta for a BSR Connection
// TODO Unmarshal without brute force
func decodeConnectionMeta(ctx context.Context, r io.Reader) (*ConnectionMeta, error) {
	const op = "bsr.decodeConnectionMeta"

	switch {
	case r == nil:
		return nil, fmt.Errorf("%s: missing connection meta file: %w", op, ErrInvalidParameter)
	}

	c := &ConnectionMeta{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		l := scanner.Text()
		if len(l) == 0 {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return nil, fmt.Errorf("%s: connection meta file contains invalid entry; expecting k: v pair:%s", op, l)
		}
		v = strings.TrimSpace(v)
		switch {
		case k == "id":
			c.Id = v
		}
	}

	return c, nil
}

// NewConnection creates a Connection container for a given connection id.
func (s *Session) NewConnection(ctx context.Context, meta *ConnectionMeta) (*Connection, error) {
	const op = "bsr.(Session).NewConnection"

	switch {
	case is.Nil(meta):
		return nil, fmt.Errorf("%s: missing connection meta: %w", op, ErrInvalidParameter)
	case meta.Id == "":
		return nil, fmt.Errorf("%s: missing connection id: %w", op, ErrInvalidParameter)
	}

	name := fmt.Sprintf(connectionFile, meta.Id)
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

// Close closes the Session container.
func (s *Session) Close(ctx context.Context) error {
	return s.container.close(ctx)
}

// Connection is a container in a bsr for a specific connection in a session
// container. It contains the files for the recorded connection.
type Connection struct {
	*container
	multiplexed bool

	Meta *ConnectionMeta
}

// ChannelMeta contains metadata about a channel in a BSR.
type ChannelMeta struct {
	Id   string
	Type string
}

func (c ChannelMeta) isValid() bool {
	switch {
	case c.Id == "":
		return false
	case c.Type == "":
		return false
	default:
		return true
	}
}

// decodeChannelMeta will populate the ChannelMeta for a BSR Channel
// TODO Unmarshal without brute force
func decodeChannelMeta(ctx context.Context, r io.Reader) (*ChannelMeta, error) {
	const op = "bsr.decodeChannelMeta"

	switch {
	case r == nil:
		return nil, fmt.Errorf("%s: missing channel meta file: %w", op, ErrInvalidParameter)
	}

	c := &ChannelMeta{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		l := scanner.Text()
		if len(l) == 0 {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return nil, fmt.Errorf("%s: channel meta file contains invalid entry; expecting k: v pair:%s", op, l)
		}
		v = strings.TrimSpace(v)
		switch {
		case k == "id":
			c.Id = v
		case k == "channelType":
			c.Type = v
		}
	}

	return c, nil
}

// NewChannel creates a Channel container for a given channel id.
func (c *Connection) NewChannel(ctx context.Context, meta *ChannelMeta) (*Channel, error) {
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

	name := fmt.Sprintf(channelFile, meta.Id)
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

// NewMessagesWriter creates a writer for recording channel messages.
func (c *Connection) NewMessagesWriter(ctx context.Context, dir Direction) (io.Writer, error) {
	const op = "bsr.(Connection).NewMessagesWriter"

	switch {
	case !ValidDirection(dir):
		return nil, fmt.Errorf("%s: invalid direction: %w", op, ErrInvalidParameter)
	}

	messagesName := fmt.Sprintf(messagesFile, dir.String())
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

	requestName := fmt.Sprintf(requestsFile, dir.String())
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

	Meta *ChannelMeta
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

	messagesName := fmt.Sprintf(messagesFile, dir.String())
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

	requestName := fmt.Sprintf(requestsFile, dir.String())
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
