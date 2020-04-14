// Package db_test provides some helper funcs for testing db integrations
package db_test

import (
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/jinzhu/gorm"
)

// Init will use gorm migrations to init tables for test models
func Init(db *gorm.DB) {
	db.AutoMigrate(&TestUser{})
	db.AutoMigrate(&TestCar{})
	db.AutoMigrate(&TestRental{})
}

// Reinit will use gorm to drop then init tables for test models
func Reinit(db *gorm.DB) {
	db.DropTableIfExists(&TestUser{})
	db.DropTableIfExists(&TestCar{})
	db.DropTableIfExists(&TestRental{})
	Init(db)
}

type TestUser struct {
	StoreTestUser
	table string `gorm:"-"`
}

func NewTestUser() (*TestUser, error) {
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, err
	}
	return &TestUser{
		StoreTestUser: StoreTestUser{
			PublicId: publicId,
		},
	}, nil
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
	StoreTestCar
	table string `gorm:"-"`
}

func NewTestCar() (*TestCar, error) {
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, err
	}
	return &TestCar{
		StoreTestCar: StoreTestCar{
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
	StoreTestRental
	table string `gorm:"-"`
}

func NewTestRental() (*TestRental, error) {
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, err
	}
	return &TestRental{
		StoreTestRental: StoreTestRental{
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
