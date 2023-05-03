// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"context"
	"errors"
	"fmt"
	"io"

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

// Scope contains information about the scope of a Boundary domain object
type Scope struct {
	PublicId            string
	Name                string // optional
	Description         string // optional
	Type                string
	ParentId            string // optional
	PrimaryAuthMethodId string // optional
}

func (s Scope) writeMeta(ctx context.Context, c *container, domainObj string) error {
	_, err := c.WriteMeta(ctx, fmt.Sprintf("%s_scope_publicId", domainObj), s.PublicId)
	if err != nil {
		return err
	}
	if s.Name != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_scope_name", domainObj), s.Name)
		if err != nil {
			return err
		}
	}
	if s.Description != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_scope_description", domainObj), s.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_scope_type", domainObj), s.Type)
	if err != nil {
		return err
	}
	if s.ParentId != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_scope_parentId", domainObj), s.ParentId)
		if err != nil {
			return err
		}
	}
	if s.PrimaryAuthMethodId != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_scope_primaryAuthMethodId", domainObj), s.PrimaryAuthMethodId)
		if err != nil {
			return err
		}
	}

	return nil
}

// User contains information about user who initiated this session
type User struct {
	PublicId    string
	Scope       Scope
	Name        string // optional field
	Description string // optional field
}

func (u User) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "user_publicId", u.PublicId)
	if err != nil {
		return err
	}
	err = u.Scope.writeMeta(ctx, c, "user")
	if err != nil {
		return err
	}
	if u.Name != "" {
		_, err = c.WriteMeta(ctx, "user_name", u.Name)
		if err != nil {
			return err
		}
	}
	if u.Description != "" {
		_, err = c.WriteMeta(ctx, "user_description", u.Description)
		if err != nil {
			return err
		}
	}

	return nil
}

// Target contains information about the target for this session
type Target struct {
	PublicId               string
	ProjectId              string
	Scope                  Scope
	Name                   string // optional field
	Description            string // optional field
	DefaultPort            uint32
	SessionMaxSeconds      uint32
	SessionConnectionLimit int32
	WorkerFilter           string // optional field
	EgressWorkerFilter     string // optional field
	IngressWorkerFilter    string // optional field
}

func (t Target) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "target_publicId", t.PublicId)
	if err != nil {
		return err
	}
	err = t.Scope.writeMeta(ctx, c, "target")
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "target_projectId", t.ProjectId)
	if err != nil {
		return err
	}
	if t.Name != "" {
		_, err = c.WriteMeta(ctx, "target_name", t.Name)
		if err != nil {
			return err
		}
	}
	if t.Description != "" {
		_, err = c.WriteMeta(ctx, "target_description", t.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, "target_defaultPort", fmt.Sprintf("%d", t.DefaultPort))
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "target_sessionMaxSeconds", fmt.Sprintf("%d", t.SessionMaxSeconds))
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "target_sessionConnectionLimit", fmt.Sprintf("%d", t.SessionConnectionLimit))
	if err != nil {
		return err
	}
	if t.WorkerFilter != "" {
		_, err = c.WriteMeta(ctx, "target_workerFilter", t.WorkerFilter)
		if err != nil {
			return err
		}
	}
	if t.IngressWorkerFilter != "" {
		_, err = c.WriteMeta(ctx, "target_ingressWorkerFilter", t.IngressWorkerFilter)
		if err != nil {
			return err
		}
	}
	if t.EgressWorkerFilter != "" {
		_, err = c.WriteMeta(ctx, "target_egressWorkerFilter", t.EgressWorkerFilter)
		if err != nil {
			return err
		}
	}

	return nil
}

// StaticHostCatalog contains information about the static host catalog for this session
type StaticHostCatalog struct {
	PublicId    string
	ProjectId   string
	Name        string // optional field
	Description string // optional field
}

func (h StaticHostCatalog) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "staticHostCatalog_publicId", h.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "staticHostCatalog_projectId", h.ProjectId)
	if err != nil {
		return err
	}
	if h.Name != "" {
		_, err = c.WriteMeta(ctx, "staticHostCatalog_name", h.Name)
		if err != nil {
			return err
		}
	}
	if h.Description != "" {
		_, err = c.WriteMeta(ctx, "staticHostCatalog_description", h.Description)
		if err != nil {
			return err
		}
	}

	return nil
}

// StaticHost contains information about the static host for this session
type StaticHost struct {
	PublicId    string
	Catalog     StaticHostCatalog
	Name        string // optional field
	Description string // optional field
	Address     string
}

func (h StaticHost) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "staticHost_publicId", h.PublicId)
	if err != nil {
		return err
	}
	err = h.Catalog.writeMeta(ctx, c)
	if err != nil {
		return err
	}
	if h.Name != "" {
		_, err = c.WriteMeta(ctx, "staticHost_name", h.Name)
		if err != nil {
			return err
		}
	}
	if h.Description != "" {
		_, err = c.WriteMeta(ctx, "staticHost_description", h.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, "staticHost_address", h.Address)
	if err != nil {
		return err
	}

	return nil
}

// DynamicHostCatalog contains information about the dynamic host catalog for this session
type DynamicHostCatalog struct {
	PublicId    string
	ProjectId   string
	Name        string // optional field
	Description string // optional field
	PluginId    string
	Attributes  string
}

func (h DynamicHostCatalog) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "dynamicHostCatalog_publicId", h.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "dynamicHostCatalog_projectId", h.ProjectId)
	if err != nil {
		return err
	}
	if h.Name != "" {
		_, err = c.WriteMeta(ctx, "dynamicHostCatalog_name", h.Name)
		if err != nil {
			return err
		}
	}
	if h.Description != "" {
		_, err = c.WriteMeta(ctx, "dynamicHostCatalog_description", h.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, "dynamicHostCatalog_pluginId", h.PluginId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "dynamicHostCatalog_attributes", h.Attributes)
	if err != nil {
		return err
	}

	return nil
}

// DynamicHost contains information about the dynamic host for this session
type DynamicHost struct {
	PublicId    string
	Catalog     DynamicHostCatalog
	Name        string // optional field
	Description string // optional field
	ExternalId  string
}

func (h DynamicHost) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "dynamicHost_publicId", h.PublicId)
	if err != nil {
		return err
	}
	err = h.Catalog.writeMeta(ctx, c)
	if err != nil {
		return err
	}
	if h.Name != "" {
		_, err = c.WriteMeta(ctx, "dynamicHost_name", h.Name)
		if err != nil {
			return err
		}
	}
	if h.Description != "" {
		_, err = c.WriteMeta(ctx, "dynamicHost_description", h.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, "dynamicHost_externalId", h.ExternalId)
	if err != nil {
		return err
	}

	return nil
}

// SessionMeta contains metadata about a session in a BSR.
type SessionMeta struct {
	Id       string
	Protocol Protocol
	User     *User
	Target   *Target
	// StaticHost and DynamicHost are mutually exclusive
	StaticHost  *StaticHost
	DynamicHost *DynamicHost
}

func (s SessionMeta) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "id", s.Id)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "protocol", s.Protocol.ToText())
	if err != nil {
		return err
	}
	err = s.User.writeMeta(ctx, c)
	if err != nil {
		return err
	}
	err = s.Target.writeMeta(ctx, c)
	if err != nil {
		return err
	}
	if !is.Nil(s.StaticHost) {
		err = s.StaticHost.writeMeta(ctx, c)
		if err != nil {
			return err
		}
	}
	if !is.Nil(s.DynamicHost) {
		err = s.DynamicHost.writeMeta(ctx, c)
		if err != nil {
			return err
		}
	}

	return nil
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
	case is.Nil(meta.User):
		return nil, fmt.Errorf("%s: missing session user: %w", op, ErrInvalidParameter)
	case is.Nil(meta.Target):
		return nil, fmt.Errorf("%s: missing session target: %w", op, ErrInvalidParameter)
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
	sc, err := s.container.container.SubContainer(ctx, name)
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

// ConnectionMeta contains metadata about a connection in a BSR.
type ConnectionMeta struct {
	Id string
}

// Connection is a container in a bsr for a specific connection in a session
// container. It contains the files for the recorded connection.
type Connection struct {
	*container
	multiplexed bool

	Meta *ConnectionMeta
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
	sc, err := c.container.container.SubContainer(ctx, name)
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

// ChannelMeta contains metadata about a channel in a BSR.
type ChannelMeta struct {
	Id   string
	Type string
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
