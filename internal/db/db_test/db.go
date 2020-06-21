// Package db_test provides some helper funcs for testing db integrations
package db_test

import (
	"github.com/hashicorp/vault/sdk/helper/base62"
	"google.golang.org/protobuf/proto"
)

type TestUser struct {
	*StoreTestUser
	table string `gorm:"-"`
}

func NewTestUser() (*TestUser, error) {
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, err
	}
	return &TestUser{
		StoreTestUser: &StoreTestUser{
			PublicId: publicId,
		},
	}, nil
}

// Clone is useful when you're retrying transactions and you need to send the user several times
func (u *TestUser) Clone() interface{} {
	s := proto.Clone(u.StoreTestUser)
	return &TestUser{
		StoreTestUser: s.(*StoreTestUser),
	}
}
func (u *TestUser) TableName() string {
	if u.table != "" {
		return u.table
	}
	return "db_test_user"
}

func (u *TestUser) SetTableName(name string) {
	if name != "" {
		u.table = name
	}
}

type TestCar struct {
	*StoreTestCar
	table string `gorm:"-"`
}

func NewTestCar() (*TestCar, error) {
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, err
	}
	return &TestCar{
		StoreTestCar: &StoreTestCar{
			PublicId: publicId,
		},
	}, nil
}

func (c *TestCar) TableName() string {
	if c.table != "" {
		return c.table
	}

	return "db_test_car"
}
func (c *TestCar) SetTableName(name string) {
	if name != "" {
		c.table = name
	}
}

type TestRental struct {
	*StoreTestRental
	table string `gorm:"-"`
}

func NewTestRental() (*TestRental, error) {
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, err
	}
	return &TestRental{
		StoreTestRental: &StoreTestRental{
			PublicId: publicId,
		},
	}, nil
}
func (r *TestRental) TableName() string {
	if r.table != "" {
		return r.table
	}

	return "db_test_rental"
}
func (r *TestRental) SetTableName(name string) {
	if name != "" {
		r.table = name
	}
}

type TestScooter struct {
	*StoreTestScooter
	table string `gorm:"-"`
}

func NewTestScooter() (*TestScooter, error) {
	privateId, err := base62.Random(20)
	if err != nil {
		return nil, err
	}
	return &TestScooter{
		StoreTestScooter: &StoreTestScooter{
			PrivateId: privateId,
		},
	}, nil
}

func (t *TestScooter) Clone() interface{} {
	s := proto.Clone(t.StoreTestScooter)
	return &TestScooter{
		StoreTestScooter: s.(*StoreTestScooter),
	}
}
func (t *TestScooter) TableName() string {
	if t.table != "" {
		return t.table
	}
	return "db_test_scooter"
}

func (t *TestScooter) SetTableName(name string) {
	if name != "" {
		t.table = name
	}
}

type Cloner interface {
	Clone() interface{}
}

type NotIder struct{}

func (i *NotIder) Clone() interface{} {
	return &NotIder{}
}
