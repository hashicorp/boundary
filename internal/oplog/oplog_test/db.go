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

// TableName overrides the table name for TestUser
func (u *TestUser) TableName() string {
	if u.Table != "" {
		return u.Table
	}
	return "oplog_test_user"
}

// SetTableName allows the table name to be overridden and makes a TestUser a ReplayableMessage
func (u *TestUser) SetTableName(n string) {
	if n != "" {
		u.Table = n
	}
}

// TableName overrides the table name for TestCar
func (c *TestCar) TableName() string {
	if c.Table != "" {
		return c.Table
	}
	return "oplog_test_car"
}

// SetTableName allows the table name to be overridden and makes a TestCar a ReplayableMessage
func (c *TestCar) SetTableName(n string) {
	if n != "" {
		c.Table = n
	}
}

// TableName overrids the table name for TestRental
func (r *TestRental) TableName() string {
	if r.Table != "" {
		return r.Table
	}
	return "oplog_test_rental"
}

// SetTableName allows the table name to be overridden and makes a TestRental a ReplayableMessage
func (r *TestRental) SetTableName(n string) {
	if n != "" {
		r.Table = n
	}
}
