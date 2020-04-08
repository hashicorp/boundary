// Package oplog_test provides some gorm helper funcs for testing oplog database integrations
package oplog_test

import "github.com/jinzhu/gorm"

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

// ReplayableTestUser is simply that: a user we can replay for tests
// the big diff is that it supports overriding the table name
type ReplayableTestUser struct {
	TestUser
	Table string `gorm:"-"`
}

// TableName overrides the table name for the test user model
func (u *ReplayableTestUser) TableName() string {
	if u.Table != "" {
		return u.Table
	}
	return "oplog_test_user"
}

func (u *ReplayableTestUser) SetTableName(name string) {
	if name != "" {
		u.Table = name
	}
}

func (*TestUser) TableName() string { return "oplog_test_user" }

// TableName overrides the table name for the test car model
func (*TestCar) TableName() string { return "oplog_test_car" }

// TableName overrids the table name for the test rental model
func (*TestRental) TableName() string { return "oplog_test_rental" }
