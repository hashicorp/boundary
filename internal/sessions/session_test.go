package sessions

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/sessions/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSession_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	userId,
		hostId,
		serverId,
		serverType,
		targetId,
		hostSetId,
		authTokenId,
		scopeId,
		address,
		port := TestSessionParams(t, conn, wrapper, iamRepo)

	type args struct {
		userId      string
		hostId      string
		serverId    string
		serverType  string
		targetId    string
		hostSetId   string
		authTokenId string
		scopeId     string
		address     string
		port        string
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
				userId:      userId,
				hostId:      hostId,
				serverId:    serverId,
				serverType:  serverType,
				targetId:    targetId,
				hostSetId:   hostSetId,
				authTokenId: authTokenId,
				scopeId:     scopeId,
				address:     address,
				port:        port,
			},
			want: &Session{
				Session: &store.Session{
					UserId:      userId,
					HostId:      hostId,
					ServerId:    serverId,
					ServerType:  serverType,
					TargetId:    targetId,
					SetId:       hostSetId,
					AuthTokenId: authTokenId,
					ScopeId:     scopeId,
					Address:     address,
					Port:        port,
				},
			},
			create: true,
		},
		{
			name: "empty-userId",
			args: args{
				hostId:      hostId,
				serverId:    serverId,
				serverType:  serverType,
				targetId:    targetId,
				hostSetId:   hostSetId,
				authTokenId: authTokenId,
				scopeId:     scopeId,
				address:     address,
				port:        port,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-hostId",
			args: args{
				userId:      userId,
				serverId:    serverId,
				serverType:  serverType,
				targetId:    targetId,
				hostSetId:   hostSetId,
				authTokenId: authTokenId,
				scopeId:     scopeId,
				address:     address,
				port:        port,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-serverId",
			args: args{
				userId:      userId,
				hostId:      hostId,
				serverType:  serverType,
				targetId:    targetId,
				hostSetId:   hostSetId,
				authTokenId: authTokenId,
				scopeId:     scopeId,
				address:     address,
				port:        port,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-serverType",
			args: args{
				userId:      userId,
				hostId:      hostId,
				serverId:    serverId,
				targetId:    targetId,
				hostSetId:   hostSetId,
				authTokenId: authTokenId,
				scopeId:     scopeId,
				address:     address,
				port:        port,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-targetId",
			args: args{
				userId:      userId,
				hostId:      hostId,
				serverId:    serverId,
				serverType:  serverType,
				hostSetId:   hostSetId,
				authTokenId: authTokenId,
				scopeId:     scopeId,
				address:     address,
				port:        port,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-hostSetId",
			args: args{
				userId:      userId,
				hostId:      hostId,
				serverId:    serverId,
				serverType:  serverType,
				targetId:    targetId,
				authTokenId: authTokenId,
				scopeId:     scopeId,
				address:     address,
				port:        port,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-authTokenId",
			args: args{
				userId:     userId,
				hostId:     hostId,
				serverId:   serverId,
				serverType: serverType,
				targetId:   targetId,
				hostSetId:  hostSetId,
				scopeId:    scopeId,
				address:    address,
				port:       port,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-scopeId",
			args: args{
				userId:      userId,
				hostId:      hostId,
				serverId:    serverId,
				serverType:  serverType,
				targetId:    targetId,
				hostSetId:   hostSetId,
				authTokenId: authTokenId,
				address:     address,
				port:        port,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-address",
			args: args{
				userId:      userId,
				hostId:      hostId,
				serverId:    serverId,
				serverType:  serverType,
				targetId:    targetId,
				hostSetId:   hostSetId,
				authTokenId: authTokenId,
				scopeId:     scopeId,
				port:        port,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-port",
			args: args{
				userId:      userId,
				hostId:      hostId,
				serverId:    serverId,
				serverType:  serverType,
				targetId:    targetId,
				hostSetId:   hostSetId,
				authTokenId: authTokenId,
				scopeId:     scopeId,
				address:     address,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := New(
				tt.args.userId,
				tt.args.hostId,
				tt.args.serverId,
				tt.args.serverType,
				tt.args.targetId,
				tt.args.hostSetId,
				tt.args.authTokenId,
				tt.args.scopeId,
				tt.args.address,
				tt.args.port,
			)
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
