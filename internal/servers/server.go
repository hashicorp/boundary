package servers

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/servers/store"
	"google.golang.org/protobuf/proto"
)

// Server is a server (Controller, Worker)
type Server struct {
	*store.Server
	tableName string `gorm:"-"`
}

// Ensure that Server implements the interfaces of:  Clonable and
// db.VetForWriter
var _ Clonable = (*Server)(nil)
var _ db.VetForWriter = (*Server)(nil)

// NewServer creates a new server in memory. No options are supported
// currently.
func NewServer(kind string, opt ...Option) (*Server, error) {
	opts := getOpts(opt...)
	s := &Server{
		Server: &store.Server{
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return s, nil
}

func allocServer() Server {
	return Server{
		Server: &store.Server{},
	}
}

// Clone creates a clone of the Server.
func (s *Server) Clone() interface{} {
	cp := proto.Clone(s.Server)
	return &Server{
		Server: cp.(*store.Server),
	}
}

// VetForWrite implements db.VetForWrite() interface for servers.
func (s *Server) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if s.PrivateId == "" {
		return fmt.Errorf("server: missing private id: %w", db.ErrInvalidParameter)
	}
	// Unlike other resources, for now at least we have the same DB structure
	// for controllers and workers, so we require a table name to be set to know
	// which table we want to write to as this type is shared by both.
	if s.tableName == "" {
		return fmt.Errorf("server: missing table name: %w", db.ErrInvalidParameter)
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name for
// servers.
func (s *Server) TableName() string {
	return s.tableName
}

// SetTableName sets the table name for the resource.
func (s *Server) SetTableName(n string) {
	s.tableName = n
}
