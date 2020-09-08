package session

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/session/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSession_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)

	type args struct {
		composedOf ComposedOf
	}
	tests := []struct {
		name          string
		args          args
		want          *Session
		wantErr       bool
		wantIsErr     error
		create        bool
		wantCreateErr bool
	}{
		{
			name: "valid",
			args: args{
				composedOf: composedOf,
			},
			want: &Session{
				Session: &store.Session{
					UserId:      composedOf.UserId,
					HostId:      composedOf.HostId,
					TargetId:    composedOf.TargetId,
					SetId:       composedOf.HostSetId,
					AuthTokenId: composedOf.AuthTokenId,
					ScopeId:     composedOf.ScopeId,
					Address:     composedOf.Address,
					Port:        composedOf.Port,
				},
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
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-hostId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.HostId = ""
					return c
				}(),
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-targetId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.TargetId = ""
					return c
				}(),
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-hostSetId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.HostSetId = ""
					return c
				}(),
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-authTokenId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.AuthTokenId = ""
					return c
				}(),
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-scopeId",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.ScopeId = ""
					return c
				}(),
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-address",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.Address = ""
					return c
				}(),
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-port",
			args: args{
				composedOf: func() ComposedOf {
					c := composedOf
					c.Port = ""
					return c
				}(),
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := New(tt.args.composedOf)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(SessionPrefix)
				require.NoError(err)
				got.PublicId = id
				err = db.New(conn).Create(context.Background(), got)
				if tt.wantCreateErr {
					assert.Error(err)
					return
				} else {
					assert.NoError(err)
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
				s := allocSession()
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
			deleteSession := allocSession()
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
			foundSession := allocSession()
			foundSession.PublicId = tt.session.PublicId
			err = rw.LookupById(context.Background(), &foundSession)
			require.Error(err)
			assert.True(errors.Is(db.ErrRecordNotFound, err))
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
		assert.True(proto.Equal(cp.(*Session).Session, s.Session))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s2 := TestDefaultSession(t, conn, wrapper, iamRepo)

		cp := s.Clone()
		assert.True(!proto.Equal(cp.(*Session).Session, s2.Session))
	})
}

func TestSession_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := DefaultSessionTableName
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
			def := allocSession()
			require.Equal(defaultTableName, def.TableName())
			s := allocSession()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
