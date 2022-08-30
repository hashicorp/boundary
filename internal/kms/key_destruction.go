package kms

import (
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

// KeyDestruction is used to interact with the key destruction
// table in the database.
type KeyDestruction struct {
	*store.KeyDestruction
}

func (k *KeyDestruction) TableName() string {
	return "kms_key_destruction"
}

// allocKeyDestruction makes an empty one in memory.
func allocKeyDestruction() KeyDestruction {
	return KeyDestruction{
		KeyDestruction: &store.KeyDestruction{},
	}
}

// Clone an KeyDestruction
func (c *KeyDestruction) Clone() *KeyDestruction {
	cp := proto.Clone(c.KeyDestruction)
	return &KeyDestruction{
		KeyDestruction: cp.(*store.KeyDestruction),
	}
}
