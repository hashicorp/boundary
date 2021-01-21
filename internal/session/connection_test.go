package session

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnection_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s := TestDefaultSession(t, conn, wrapper, iamRepo)

	type args struct {
		sessionId          string
		clientTcpAddress   string
		clientTcpPort      uint32
		endpointTcpAddress string
		endpointTcpPort    uint32
	}
	tests := []struct {
		name          string
		args          args
		want          *Connection
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name: "valid",
			args: args{
				sessionId:          s.PublicId,
				clientTcpAddress:   "127.0.0.1",
				clientTcpPort:      22,
				endpointTcpAddress: "127.0.0.1",
				endpointTcpPort:    2222,
			},
			want: &Connection{
				SessionId:          s.PublicId,
				ClientTcpAddress:   "127.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "127.0.0.1",
				EndpointTcpPort:    2222,
			},
			create: true,
		},
		{
			name: "empty-session-id",
			args: args{
				clientTcpAddress:   "127.0.0.1",
				clientTcpPort:      22,
				endpointTcpAddress: "127.0.0.1",
				endpointTcpPort:    2222,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-client-address",
			args: args{
				sessionId:          s.PublicId,
				clientTcpPort:      22,
				endpointTcpAddress: "127.0.0.1",
				endpointTcpPort:    2222,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-client-port",
			args: args{
				sessionId:          s.PublicId,
				clientTcpAddress:   "localhost",
				endpointTcpAddress: "127.0.0.1",
				endpointTcpPort:    2222,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-endpoint-address",
			args: args{
				sessionId:        s.PublicId,
				clientTcpAddress: "localhost",
				clientTcpPort:    22,
				endpointTcpPort:  2222,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-endpoint-port",
			args: args{
				sessionId:          s.PublicId,
				clientTcpAddress:   "localhost",
				clientTcpPort:      22,
				endpointTcpAddress: "127.0.0.1",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewConnection(
				tt.args.sessionId,
				tt.args.clientTcpAddress,
				tt.args.clientTcpPort,
				tt.args.endpointTcpAddress,
				tt.args.endpointTcpPort,
			)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(ConnectionPrefix)
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

func TestConnection_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s := TestDefaultSession(t, conn, wrapper, iamRepo)

	tests := []struct {
		name            string
		connection      *Connection
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			connection:      TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			connection: func() *Connection {
				c := AllocConnection()
				id, err := db.NewPublicId(ConnectionPrefix)
				require.NoError(t, err)
				c.PublicId = id
				return &c
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteConnection := AllocConnection()
			deleteConnection.PublicId = tt.connection.PublicId
			deletedRows, err := rw.Delete(context.Background(), &deleteConnection)
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
			foundConnection := AllocConnection()
			foundConnection.PublicId = tt.connection.PublicId
			err = rw.LookupById(context.Background(), &foundConnection)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestConnection_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222)
		cp := c.Clone()
		assert.Equal(cp.(*Connection), c)
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222)
		c2 := TestConnection(t, conn, s.PublicId, "127.0.0.1", 80, "127.0.0.1", 8080)

		cp := c.Clone()
		assert.NotEqual(cp.(*Connection), c2)
	})
}

func TestConnection_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultConnectionTableName
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
			def := AllocConnection()
			require.Equal(defaultTableName, def.TableName())
			c := AllocConnection()
			c.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, c.TableName())
		})
	}
}
