package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	mathrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultSessionTableName = "session"
)

// ComposedOf defines the boundary data that is referenced to compose a session.
type ComposedOf struct {
	// UserId of the session
	UserId string
	// HostId of the session
	HostId string
	// TargetId of the session
	TargetId string
	// HostSetId of the session
	HostSetId string
	// AuthTokenId of the session
	AuthTokenId string
	// ProjectId of the session
	ProjectId string
	// Endpoint. This is generated by the target, but is not stored in the
	// warehouse as the worker may need to e.g. resolve DNS. This is to round
	// trip the information to the worker when it validates a session.
	Endpoint string
	// Expiration time for the session
	ExpirationTime *timestamp.Timestamp
	// Max connections for the session
	ConnectionLimit int32
	// Worker filter. Active filter when the session was created, used to
	// validate the session via the same set of rules at consumption time as
	// existed at creation time. Round tripping it through here saves a lookup
	// in the DB. It is not stored in the warehouse.
	WorkerFilter string
	// DynamicCredentials are dynamic credentials that will be retrieved
	// for the session. DynamicCredentials optional.
	DynamicCredentials []*DynamicCredential
	// StaticCredentials are static credentials that will be retrieved
	// for the session. StaticCredentials optional.
	StaticCredentials []*StaticCredential
}

// Session contains information about a user's session with a target
type Session struct {
	// PublicId is used to access the session via an API
	PublicId string `json:"public_id,omitempty" gorm:"primary_key"`
	// UserId for the session
	UserId string `json:"user_id,omitempty" gorm:"default:null"`
	// HostId of the session
	HostId string `json:"host_id,omitempty" gorm:"default:null"`
	// TargetId for the session
	TargetId string `json:"target_id,omitempty" gorm:"default:null"`
	// HostSetId for the session
	HostSetId string `json:"host_set_id,omitempty" gorm:"default:null"`
	// AuthTokenId for the session
	AuthTokenId string `json:"auth_token_id,omitempty" gorm:"default:null"`
	// ProjectId for the session
	ProjectId string `json:"project_id,omitempty" gorm:"default:null"`
	// Certificate to use when connecting (or if using custom certs, to
	// serve as the "login"). Raw DER bytes.  Private key is not, and should not be
	// stored in the database.
	Certificate []byte `json:"certificate,omitempty" gorm:"default:null"`
	// ExpirationTime - after this time the connection will be expired, e.g. forcefully terminated
	ExpirationTime *timestamp.Timestamp `json:"expiration_time,omitempty" gorm:"default:null"`
	// CtTofuToken is the ciphertext Tofutoken value stored in the database
	CtTofuToken []byte `json:"ct_tofu_token,omitempty" gorm:"column:tofu_token;default:null" wrapping:"ct,tofu_token"`
	// TofuToken - plain text of the "trust on first use" token for session
	TofuToken []byte `json:"tofu_token,omitempty" gorm:"-" wrapping:"pt,tofu_token"`
	// termination_reason for the session
	TerminationReason string `json:"termination_reason,omitempty" gorm:"default:null"`
	// CreateTime from the RDBMS
	CreateTime *timestamp.Timestamp `json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// UpdateTime from the RDBMS
	UpdateTime *timestamp.Timestamp `json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// Version for the session
	Version uint32 `json:"version,omitempty" gorm:"default:null"`
	// Endpoint
	Endpoint string `json:"-" gorm:"default:null"`
	// Maximum number of connections in a session
	ConnectionLimit int32 `json:"connection_limit,omitempty" gorm:"default:null"`
	// Worker filter
	WorkerFilter string `json:"-" gorm:"default:null"`

	// key_id is the key ID that was used for the encryption operation. It can be
	// used to identify a specific version of the key needed to decrypt the value,
	// which is useful for caching purposes.
	// @inject_tag: `gorm:"not_null"`
	KeyId string `json:"key_id,omitempty" gorm:"default:null"`

	// States for the session which are for read only and are ignored during
	// write operations
	States []*State `gorm:"-"`

	// DynamicCredentials for the session.
	DynamicCredentials []*DynamicCredential `gorm:"-"`

	// StaticCredentials for the session.
	StaticCredentials []*StaticCredential `gorm:"-"`

	// Connections for the session are for read only and are ignored during write operations
	Connections []*Connection `gorm:"-"`

	tableName string `gorm:"-"`
}

func (s Session) GetPublicId() string {
	return s.PublicId
}

func (s Session) GetProjectId() string {
	return s.ProjectId
}

func (s Session) GetUserId() string {
	return s.UserId
}

var (
	_ Cloneable                     = (*Session)(nil)
	_ db.VetForWriter               = (*Session)(nil)
	_ boundary.AuthzProtectedEntity = (*Session)(nil)
)

// New creates a new in memory session.
func New(c ComposedOf, _ ...Option) (*Session, error) {
	const op = "session.New"
	s := Session{
		UserId:             c.UserId,
		HostId:             c.HostId,
		TargetId:           c.TargetId,
		HostSetId:          c.HostSetId,
		AuthTokenId:        c.AuthTokenId,
		ProjectId:          c.ProjectId,
		Endpoint:           c.Endpoint,
		ExpirationTime:     c.ExpirationTime,
		ConnectionLimit:    c.ConnectionLimit,
		WorkerFilter:       c.WorkerFilter,
		DynamicCredentials: c.DynamicCredentials,
		StaticCredentials:  c.StaticCredentials,
	}
	if err := s.validateNewSession(); err != nil {
		return nil, errors.WrapDeprecated(err, op)
	}
	return &s, nil
}

// AllocSession will allocate a Session
func AllocSession() Session {
	return Session{}
}

// Clone creates a clone of the Session
func (s *Session) Clone() interface{} {
	clone := &Session{
		PublicId:          s.PublicId,
		UserId:            s.UserId,
		HostId:            s.HostId,
		TargetId:          s.TargetId,
		HostSetId:         s.HostSetId,
		AuthTokenId:       s.AuthTokenId,
		ProjectId:         s.ProjectId,
		TerminationReason: s.TerminationReason,
		Version:           s.Version,
		Endpoint:          s.Endpoint,
		ConnectionLimit:   s.ConnectionLimit,
		WorkerFilter:      s.WorkerFilter,
		KeyId:             s.KeyId,
	}
	if len(s.States) > 0 {
		clone.States = make([]*State, 0, len(s.States))
		for _, ss := range s.States {
			cp := ss.Clone().(*State)
			clone.States = append(clone.States, cp)
		}
	}
	if len(s.DynamicCredentials) > 0 {
		clone.DynamicCredentials = make([]*DynamicCredential, 0, len(s.DynamicCredentials))
		for _, sc := range s.DynamicCredentials {
			cp := sc.clone()
			clone.DynamicCredentials = append(clone.DynamicCredentials, cp)
		}
	}
	if len(s.StaticCredentials) > 0 {
		clone.StaticCredentials = make([]*StaticCredential, 0, len(s.StaticCredentials))
		for _, sc := range s.StaticCredentials {
			cp := sc.clone()
			clone.StaticCredentials = append(clone.StaticCredentials, cp)
		}
	}
	if s.TofuToken != nil {
		clone.TofuToken = make([]byte, len(s.TofuToken))
		copy(clone.TofuToken, s.TofuToken)
	}
	if s.CtTofuToken != nil {
		clone.CtTofuToken = make([]byte, len(s.CtTofuToken))
		copy(clone.CtTofuToken, s.CtTofuToken)
	}
	if s.Certificate != nil {
		clone.Certificate = make([]byte, len(s.Certificate))
		copy(clone.Certificate, s.Certificate)
	}
	if s.ExpirationTime != nil {
		clone.ExpirationTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: s.ExpirationTime.Timestamp.Seconds,
				Nanos:   s.ExpirationTime.Timestamp.Nanos,
			},
		}
	}
	if s.CreateTime != nil {
		clone.CreateTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: s.CreateTime.Timestamp.Seconds,
				Nanos:   s.CreateTime.Timestamp.Nanos,
			},
		}
	}
	if s.UpdateTime != nil {
		clone.UpdateTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: s.UpdateTime.Timestamp.Seconds,
				Nanos:   s.UpdateTime.Timestamp.Nanos,
			},
		}
	}
	return clone
}

// VetForWrite implements db.VetForWrite() interface and validates the session
// before it's written.
func (s *Session) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "session.(Session).VetForWrite"
	opts := db.GetOpts(opt...)
	if s.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	switch opType {
	case db.CreateOp:
		if err := s.validateNewSession(); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if len(s.Certificate) == 0 {
			return errors.New(ctx, errors.InvalidParameter, op, "missing certificate")
		}
	case db.UpdateOp:
		switch {
		case contains(opts.WithFieldMaskPaths, "PublicId"):
			return errors.New(ctx, errors.InvalidParameter, op, "public id is immutable")
		case contains(opts.WithFieldMaskPaths, "UserId"):
			return errors.New(ctx, errors.InvalidParameter, op, "user id is immutable")
		case contains(opts.WithFieldMaskPaths, "HostId"):
			return errors.New(ctx, errors.InvalidParameter, op, "host id is immutable")
		case contains(opts.WithFieldMaskPaths, "TargetId"):
			return errors.New(ctx, errors.InvalidParameter, op, "target id is immutable")
		case contains(opts.WithFieldMaskPaths, "HostSetId"):
			return errors.New(ctx, errors.InvalidParameter, op, "host set id is immutable")
		case contains(opts.WithFieldMaskPaths, "AuthTokenId"):
			return errors.New(ctx, errors.InvalidParameter, op, "auth token id is immutable")
		case contains(opts.WithFieldMaskPaths, "Certificate"):
			return errors.New(ctx, errors.InvalidParameter, op, "certificate is immutable")
		case contains(opts.WithFieldMaskPaths, "CreateTime"):
			return errors.New(ctx, errors.InvalidParameter, op, "create time is immutable")
		case contains(opts.WithFieldMaskPaths, "UpdateTime"):
			return errors.New(ctx, errors.InvalidParameter, op, "update time is immutable")
		case contains(opts.WithFieldMaskPaths, "Endpoint"):
			return errors.New(ctx, errors.InvalidParameter, op, "endpoint is immutable")
		case contains(opts.WithFieldMaskPaths, "ExpirationTime"):
			return errors.New(ctx, errors.InvalidParameter, op, "expiration time is immutable")
		case contains(opts.WithFieldMaskPaths, "ConnectionLimit"):
			return errors.New(ctx, errors.InvalidParameter, op, "connection limit is immutable")
		case contains(opts.WithFieldMaskPaths, "WorkerFilter"):
			return errors.New(ctx, errors.InvalidParameter, op, "worker filter is immutable")
		case contains(opts.WithFieldMaskPaths, "DynamicCredentials"):
			return errors.New(ctx, errors.InvalidParameter, op, "dynamic credentials are immutable")
		case contains(opts.WithFieldMaskPaths, "StaticCredentials"):
			return errors.New(ctx, errors.InvalidParameter, op, "static credentials are immutable")
		case contains(opts.WithFieldMaskPaths, "TerminationReason"):
			if _, err := convertToReason(s.TerminationReason); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (s *Session) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultSessionTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (s *Session) SetTableName(n string) {
	s.tableName = n
}

// validateNewSession checks everything but the session's PublicId
func (s *Session) validateNewSession() error {
	const op = "session.(Session).validateNewSession"
	if s.UserId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing user id")
	}
	if s.HostId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing host id")
	}
	if s.TargetId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing target id")
	}
	if s.HostSetId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing host set id")
	}
	if s.AuthTokenId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing auth token id")
	}
	if s.ProjectId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing project id")
	}
	if s.Endpoint == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing endpoint")
	}
	if s.ExpirationTime.GetTimestamp().AsTime().IsZero() {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing expiration time")
	}
	if s.TerminationReason != "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "termination reason must be empty")
	}
	if s.TofuToken != nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "tofu token must be empty")
	}
	if s.CtTofuToken != nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "ct must be empty")
	}
	// It is okay for the worker filter to be empty, so it is not checked here.
	return nil
}

func contains(ss []string, t string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, t) {
			return true
		}
	}
	return false
}

// newCert creates a new session certificate. If addresses are supplied, they will be parsed and added to IP or DNS SANs as appropriate.
func newCert(ctx context.Context, wrapper wrapping.Wrapper, userId, jobId string, addresses []string, exp time.Time) (ed25519.PrivateKey, []byte, error) {
	const op = "session.newCert"
	if wrapper == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing wrapper")
	}
	if userId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	if jobId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing job id")
	}
	if len(addresses) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing addresses")
	}
	pubKey, privKey, err := DeriveED25519Key(ctx, wrapper, userId, jobId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	template := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              []string{jobId},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              exp,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	for _, addr := range addresses {
		// First ensure we aren't looking at ports, regardless of IP or not
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			if strings.Contains(err.Error(), "missing port") {
				host = addr
			} else {
				return nil, nil, errors.Wrap(ctx, err, op)
			}
		}
		// Now figure out if it's an IP address or not. If ParseIP likes it, add
		// to IP SANs. Otherwise DNS SANs.
		ip := net.ParseIP(host)
		switch ip {
		case nil:
			template.DNSNames = append(template.DNSNames, host)
		default:
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.GenCert))
	}
	return privKey, certBytes, nil
}

func (s *Session) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "session.(Session).encrypt"
	if err := structwrapping.WrapStruct(ctx, cipher, s, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("error getting cipher key id"))
	}
	s.KeyId = keyId
	return nil
}

func (s *Session) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "session.(Session).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, s, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

type sessionListView struct {
	// Session fields
	PublicId          string               `json:"public_id,omitempty" gorm:"primary_key"`
	UserId            string               `json:"user_id,omitempty" gorm:"default:null"`
	HostId            string               `json:"host_id,omitempty" gorm:"default:null"`
	TargetId          string               `json:"target_id,omitempty" gorm:"default:null"`
	HostSetId         string               `json:"host_set_id,omitempty" gorm:"default:null"`
	AuthTokenId       string               `json:"auth_token_id,omitempty" gorm:"default:null"`
	ProjectId         string               `json:"project_id,omitempty" gorm:"default:null"`
	Certificate       []byte               `json:"certificate,omitempty" gorm:"default:null"`
	ExpirationTime    *timestamp.Timestamp `json:"expiration_time,omitempty" gorm:"default:null"`
	CtTofuToken       []byte               `json:"ct_tofu_token,omitempty" gorm:"column:tofu_token;default:null" wrapping:"ct,tofu_token"`
	TofuToken         []byte               `json:"tofu_token,omitempty" gorm:"-" wrapping:"pt,tofu_token"`
	TerminationReason string               `json:"termination_reason,omitempty" gorm:"default:null"`
	CreateTime        *timestamp.Timestamp `json:"create_time,omitempty" gorm:"default:current_timestamp"`
	UpdateTime        *timestamp.Timestamp `json:"update_time,omitempty" gorm:"default:current_timestamp"`
	Version           uint32               `json:"version,omitempty" gorm:"default:null"`
	Endpoint          string               `json:"-" gorm:"default:null"`
	ConnectionLimit   int32                `json:"connection_limit,omitempty" gorm:"default:null"`
	KeyId             string               `json:"key_id,omitempty" gorm:"default:null"`

	// State fields
	Status          string               `json:"state,omitempty" gorm:"column:state"`
	PreviousEndTime *timestamp.Timestamp `json:"previous_end_time,omitempty" gorm:"default:current_timestamp"`
	StartTime       *timestamp.Timestamp `json:"start_time,omitempty" gorm:"default:current_timestamp;primary_key"`
	EndTime         *timestamp.Timestamp `json:"end_time,omitempty" gorm:"default:current_timestamp"`
}

// TableName returns the tablename to override the default gorm table name
func (s *sessionListView) TableName() string {
	return "session_list"
}
