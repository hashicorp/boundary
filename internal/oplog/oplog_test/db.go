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

// TableName overrides the table name for the test user model
func (*TestUser) TableName() string { return "oplog_test_user" }

// TableName overrides the table name for the test car model
func (*TestCar) TableName() string { return "oplog_test_car" }

// TableName overrids the table name for the test rental model
func (*TestRental) TableName() string { return "oplog_test_rental" }
