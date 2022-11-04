package session

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSession_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)

	composedOf := testSessionCredentialParams(t, conn, wrapper, iamRepo)
	exp := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(time.Hour))}

	defaultAddresses := []string{"1.2.3.4", "a.b.c.d"}
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
			name: "valid",
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
			},
			create: true,
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
			name: "empty-hostId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.HostId = ""
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
			name: "empty-hostSetId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.HostSetId = ""
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
			},
			wantAddrErr: true,
			wantIsErr:   errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			assert, require := assert.New(t), require.New(t)
			got, err := New(tt.args.composedOf)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(SessionPrefix)
				require.NoError(err)
				got.PublicId = id
				wrapper, err := kmsCache.GetWrapper(ctx, tt.args.composedOf.ProjectId, kms.KeyPurposeSessions)
				require.NoError(err)
				privKey, certBytes, err := newCert(ctx, wrapper, got.UserId, id, tt.args.addresses, composedOf.ExpirationTime.Timestamp.AsTime(), rand.Reader)
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
				id, err := db.NewPublicId(SessionPrefix)
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
			deletedRows, err := rw.Delete(context.Background(), &deleteSession)
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
