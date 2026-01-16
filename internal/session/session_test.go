// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSession_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	composedOf := testSessionCredentialParams(t, conn, wrapper, iamRepo)
	exp := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(time.Hour))}

	defaultAddresses := []string{"1.2.3.4", "a.b.c.d", "[2001:4860:4860::8888]", "[2001:4860:4860:0:0:0:0:8888]"}
	type args struct {
		composedOf ComposedOf
		addresses  []string
		opt        []Option
	}
	tests := []struct {
		name          string
		args          args
		want          *Session
		wantErr       bool
		wantAddrErr   bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name: "valid-hostset-host-ipv4",
			args: args{
				composedOf: composedOf,
				opt:        []Option{WithExpirationTime(exp)},
				addresses:  defaultAddresses,
			},
			want: &Session{
				UserId:             composedOf.UserId,
				HostId:             composedOf.HostId,
				TargetId:           composedOf.TargetId,
				HostSetId:          composedOf.HostSetId,
				AuthTokenId:        composedOf.AuthTokenId,
				ProjectId:          composedOf.ProjectId,
				Endpoint:           "tcp://127.0.0.1:22",
				ExpirationTime:     composedOf.ExpirationTime,
				ConnectionLimit:    composedOf.ConnectionLimit,
				DynamicCredentials: composedOf.DynamicCredentials,
				StaticCredentials:  composedOf.StaticCredentials,
				CorrelationId:      composedOf.CorrelationId,
			},
			create: true,
		},
		{
			name: "valid-hostset-host-ipv6",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.Endpoint = "tcp://[::1]:22"
					return c
				}(),
				opt:       []Option{WithExpirationTime(exp)},
				addresses: defaultAddresses,
			},
			want: &Session{
				UserId:             composedOf.UserId,
				HostId:             composedOf.HostId,
				TargetId:           composedOf.TargetId,
				HostSetId:          composedOf.HostSetId,
				AuthTokenId:        composedOf.AuthTokenId,
				ProjectId:          composedOf.ProjectId,
				Endpoint:           "tcp://[::1]:22",
				ExpirationTime:     composedOf.ExpirationTime,
				ConnectionLimit:    composedOf.ConnectionLimit,
				DynamicCredentials: composedOf.DynamicCredentials,
				StaticCredentials:  composedOf.StaticCredentials,
				CorrelationId:      composedOf.CorrelationId,
			},
			create: true,
		},
		{
			name: "valid-target-address",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.HostSetId = ""
					c.HostId = ""
					return c
				}(),
				opt:       []Option{WithExpirationTime(exp)},
				addresses: defaultAddresses,
			},
			want: &Session{
				UserId:             composedOf.UserId,
				HostId:             "",
				HostSetId:          "",
				TargetId:           composedOf.TargetId,
				AuthTokenId:        composedOf.AuthTokenId,
				ProjectId:          composedOf.ProjectId,
				Endpoint:           "tcp://127.0.0.1:22",
				ExpirationTime:     composedOf.ExpirationTime,
				ConnectionLimit:    composedOf.ConnectionLimit,
				DynamicCredentials: composedOf.DynamicCredentials,
				StaticCredentials:  composedOf.StaticCredentials,
				CorrelationId:      composedOf.CorrelationId,
			},
			create: true,
		},
		{
			name: "invalid-missing-target-address-host-source",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.HostSetId = ""
					c.HostId = ""
					c.Endpoint = ""
					return c
				}(),
				addresses: defaultAddresses,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-userId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.UserId = ""
					return c
				}(),
				addresses: defaultAddresses,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-targetId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.TargetId = ""
					return c
				}(),
				addresses: defaultAddresses,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-authTokenId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.AuthTokenId = ""
					return c
				}(),
				addresses: defaultAddresses,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-projectId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.ProjectId = ""
					return c
				}(),
				addresses: defaultAddresses,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-correlationId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.CorrelationId = ""
					return c
				}(),
				addresses: defaultAddresses,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-addresses",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					return c
				}(),
			},
			want: &Session{
				UserId:             composedOf.UserId,
				HostId:             composedOf.HostId,
				TargetId:           composedOf.TargetId,
				HostSetId:          composedOf.HostSetId,
				AuthTokenId:        composedOf.AuthTokenId,
				ProjectId:          composedOf.ProjectId,
				Endpoint:           "tcp://127.0.0.1:22",
				ExpirationTime:     composedOf.ExpirationTime,
				ConnectionLimit:    composedOf.ConnectionLimit,
				DynamicCredentials: composedOf.DynamicCredentials,
				StaticCredentials:  composedOf.StaticCredentials,
				CorrelationId:      composedOf.CorrelationId,
			},
			wantAddrErr: true,
			wantIsErr:   errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			assert, require := assert.New(t), require.New(t)
			got, err := New(ctx, tt.args.composedOf)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(ctx, globals.SessionPrefix)
				require.NoError(err)
				got.PublicId = id
				privKey, certBytes, err := newCert(ctx, id, tt.args.addresses, composedOf.ExpirationTime.Timestamp.AsTime(), rand.Reader)
				if tt.wantAddrErr {
					require.Error(err)
					assert.True(errors.Match(errors.T(tt.wantIsErr), err))
					return
				}
				require.NoError(err)
				got.Certificate = certBytes
				got.CertificatePrivateKey = privKey
				err = db.New(conn).Create(ctx, got)
				if tt.wantCreateErr {
					assert.Error(err)
					return
				} else {
					assert.NoError(err)
				}

				if len(tt.args.addresses) > 0 {
					cert, err := x509.ParseCertificate(certBytes)
					require.NoError(err)
					// Session ID is always encoded, hence the +1
					assert.Equal(len(tt.args.addresses)+1, len(cert.DNSNames)+len(cert.IPAddresses))
				}
			}
		})
	}
}

func TestSession_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	tests := []struct {
		name            string
		session         *Session
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			session:         TestDefaultSession(t, conn, wrapper, iamRepo),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			session: func() *Session {
				s := AllocSession()
				id, err := db.NewPublicId(ctx, globals.SessionPrefix)
				require.NoError(t, err)
				s.PublicId = id
				return &s
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteSession := AllocSession()
			deleteSession.PublicId = tt.session.PublicId
			deletedRows, err := rw.Delete(ctx, &deleteSession)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundSession := AllocSession()
			foundSession.PublicId = tt.session.PublicId
			err = rw.LookupById(context.Background(), &foundSession)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestSession_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		cp := s.Clone()
		assert.Equal(cp.(*Session), s)
	})
	t.Run("with-correlation-id", func(t *testing.T) {
		assert := assert.New(t)
		composedOf := TestSessionParams(t, conn, wrapper, iamRepo)
		corId, err := uuid.GenerateUUID()
		require.NoError(t, err)
		composedOf.CorrelationId = corId
		s := TestSession(t, conn, wrapper, composedOf)
		cp := s.Clone()
		assert.Equal(cp.(*Session), s)
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s2 := TestDefaultSession(t, conn, wrapper, iamRepo)

		cp := s.Clone()
		assert.NotEqual(cp.(*Session), s2)
	})
}

func TestSession_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultSessionTableName
	tests := []struct {
		name      string
		setNameTo string
		want      string
	}{
		{
			name:      "new-name",
			setNameTo: "new-name",
			want:      "new-name",
		},
		{
			name:      "reset to default",
			setNameTo: "",
			want:      defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := AllocSession()
			require.Equal(defaultTableName, def.TableName())
			s := AllocSession()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func Test_newCert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	jobId := "job-id"
	addresses := []string{"127.0.0.1", "localhost"}
	expireTime := time.Now().Add(5 * time.Minute)
	reader := rand.Reader

	t.Run("fails-on-invalid-job-id", func(t *testing.T) {
		_, _, err := newCert(ctx, "", addresses, expireTime, reader)
		require.Error(t, err)
	})
	t.Run("fails-on-invalid-addresses", func(t *testing.T) {
		_, _, err := newCert(ctx, jobId, nil, expireTime, reader)
		require.Error(t, err)
	})
	t.Run("fails-on-invalid-expiry", func(t *testing.T) {
		_, _, err := newCert(ctx, jobId, addresses, time.Time{}, reader)
		require.Error(t, err)
	})
	t.Run("fails-on-invalid-random-reader", func(t *testing.T) {
		_, _, err := newCert(ctx, jobId, addresses, expireTime, nil)
		require.Error(t, err)
	})
	t.Run("succeeds-on-valid-inputs", func(t *testing.T) {
		key, cert, err := newCert(ctx, jobId, addresses, expireTime, reader)
		require.NoError(t, err)
		parsedCert, err := x509.ParseCertificate(cert)
		require.NoError(t, err)
		assert.Equal(t, parsedCert.DNSNames, []string{jobId, "localhost"})
		assert.Equal(t, parsedCert.IPAddresses, []net.IP{{127, 0, 0, 1}})
		assert.True(t, parsedCert.NotAfter.Equal(expireTime.Truncate(time.Second)), "NotAfter (%q) != expireTime (%q)", parsedCert.NotAfter.Format(time.RFC3339Nano), expireTime.Format(time.RFC3339Nano))
		assert.Equal(t, parsedCert.PublicKey.(crypto.PublicKey), ed25519.PrivateKey(key).Public())
	})
}

func TestProxyCertificate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	sId := "test-session-id"
	cert := make([]byte, 20)
	if _, err := rand.Read(cert); err != nil {
		require.NotNil(t, err)
	}
	privKey := make([]byte, 20)
	if _, err := rand.Read(privKey); err != nil {
		require.NotNil(t, err)
	}

	tests := []struct {
		name            string
		sessionId       string
		certificate     []byte
		privKey         []byte
		expected        *ProxyCertificate
		wantErr         bool
		wantErrContains string
	}{
		{
			name:        "valid-target-cert",
			sessionId:   sId,
			certificate: cert,
			privKey:     privKey,
			expected: &ProxyCertificate{
				SessionId:   sId,
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		{
			name:            "missing-session-id",
			certificate:     cert,
			privKey:         privKey,
			wantErr:         true,
			wantErrContains: "missing session id",
		},
		{
			name:            "missing-cert",
			sessionId:       sId,
			privKey:         privKey,
			wantErr:         true,
			wantErrContains: "missing certificate",
		},
		{
			name:            "missing-priv-key",
			sessionId:       sId,
			certificate:     cert,
			wantErr:         true,
			wantErrContains: "missing private key",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			gotCert, err := NewProxyCertificate(ctx, tt.sessionId, tt.privKey, tt.certificate)

			if tt.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(gotCert)
			assert.Equal(tt.expected.SessionId, gotCert.SessionId)
			assert.Equal(tt.expected.Certificate, gotCert.Certificate)
		})
	}
}
