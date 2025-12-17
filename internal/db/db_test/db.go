// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package db_test provides some helper funcs for testing db integrations
package db_test

import (
	"errors"

	"github.com/hashicorp/go-secure-stdlib/base62"
	"google.golang.org/protobuf/proto"
)

const (
	defaultUserTablename             = "db_test_user"
	defaultCarTableName              = "db_test_car"
	defaultRentalTableName           = "db_test_rental"
	defaultScooterTableName          = "db_test_scooter"
	defaultAccessoryTableName        = "db_test_accessory"
	defaultScooterAccessoryTableName = "db_test_scooter_accessory"
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

func AllocTestUser() TestUser {
	return TestUser{
		StoreTestUser: &StoreTestUser{},
	}
}

// Clone is useful when you're retrying transactions and you need to send the user several times
func (u *TestUser) Clone() any {
	s := proto.Clone(u.StoreTestUser)
	return &TestUser{
		StoreTestUser: s.(*StoreTestUser),
	}
}

func (u *TestUser) TableName() string {
	if u.table != "" {
		return u.table
	}
	return defaultUserTablename
}

func (u *TestUser) SetTableName(name string) {
	switch name {
	case "":
		u.table = defaultUserTablename
	default:
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

	return defaultCarTableName
}

func (c *TestCar) SetTableName(name string) {
	c.table = name
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

	return defaultRentalTableName
}

func (r *TestRental) SetTableName(name string) {
	r.table = name
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

func (t *TestScooter) Clone() any {
	s := proto.Clone(t.StoreTestScooter)
	return &TestScooter{
		StoreTestScooter: s.(*StoreTestScooter),
	}
}

func (t *TestScooter) TableName() string {
	if t.table != "" {
		return t.table
	}
	return defaultScooterTableName
}

func (t *TestScooter) SetTableName(name string) {
	t.table = name
}

type TestAccessory struct {
	*StoreTestAccessory
	table string `gorm:"-"`
}

func NewTestAccessory(description string) (*TestAccessory, error) {
	if description == "" {
		return nil, errors.New("missing description")
	}
	return &TestAccessory{StoreTestAccessory: &StoreTestAccessory{Description: description}}, nil
}

func (t *TestAccessory) Clone() any {
	s := proto.Clone(t.StoreTestAccessory)
	return &TestAccessory{
		StoreTestAccessory: s.(*StoreTestAccessory),
	}
}

func (t *TestAccessory) TableName() string {
	if t.table != "" {
		return t.table
	}
	return defaultAccessoryTableName
}

func (t *TestAccessory) SetTableName(name string) {
	t.table = name
}

type TestScooterAccessory struct {
	*StoreTestScooterAccessory
	table string `gorm:"-"`
}

func NewTestScooterAccessory(scooterId, accessoryId uint32) (*TestScooterAccessory, error) {
	if accessoryId == 0 {
		return nil, errors.New("mssing accessory id")
	}
	return &TestScooterAccessory{
		StoreTestScooterAccessory: &StoreTestScooterAccessory{
			ScooterId:   scooterId,
			AccessoryId: accessoryId,
		},
	}, nil
}

func (t *TestScooterAccessory) Clone() any {
	s := proto.Clone(t.StoreTestScooterAccessory)
	return &TestScooterAccessory{
		StoreTestScooterAccessory: s.(*StoreTestScooterAccessory),
	}
}

func (t *TestScooterAccessory) TableName() string {
	if t.table != "" {
		return t.table
	}
	return defaultScooterAccessoryTableName
}

func (t *TestScooterAccessory) SetTableName(name string) {
	t.table = name
}

type Cloner interface {
	Clone() any
}

type NotIder struct{}

func (i *NotIder) Clone() any {
	return &NotIder{}
}
