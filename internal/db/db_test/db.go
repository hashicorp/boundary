// Package db_test provides some helper funcs for testing db integrations
package db_test

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
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
func (u *TestUser) Clone() *TestUser {
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

// Scan supports Timestamps for oplogs
func (ts *Timestamp) Scan(value interface{}) error {
	switch t := value.(type) {
	case time.Time:
		var err error
		ts.Timestamp, err = ptypes.TimestampProto(t) // google proto version
		if err != nil {
			return fmt.Errorf("error converting the timestamp: %w", err)
		}
	default:
		return errors.New("Not a protobuf Timestamp")
	}
	return nil
}

// Value supports Timestamps for oplogs
func (ts *Timestamp) Value() (driver.Value, error) {
	if ts == nil {
		return nil, nil
	}
	return ptypes.Timestamp(ts.Timestamp)
}
