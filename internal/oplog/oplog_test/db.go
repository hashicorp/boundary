// Package oplog_test provides some gorm helper funcs for testing oplog database integrations
package oplog_test

import "gorm.io/gorm"

const (
	defaultTestUserTableName   = "oplog_test_user"
	defaultTestCarTableName    = "oplog_test_car"
	defaultTestRentalTableName = "oplog_test_rental"
)

// Init will use gorm migrations to init tables for test models
func Init(db *gorm.DB) {
	db.AutoMigrate(&TestUser{})
	db.AutoMigrate(&TestCar{})
	db.AutoMigrate(&TestRental{})
}

// Reinit will use gorm to drop then init tables for test models
func Reinit(db *gorm.DB) {
	// Migrator.DropTable is actually "drop table <name> if exists"
	_ = db.Migrator().DropTable(&TestUser{})
	_ = db.Migrator().DropTable(&TestCar{})
	_ = db.Migrator().DropTable(&TestRental{})
	Init(db)
}

// TableName overrides the table name for TestUser
func (u *TestUser) TableName() string {
	if u.Table != "" {
		return u.Table
	}
	return defaultTestUserTableName
}

// SetTableName allows the table name to be overridden and makes a TestUser a
// ReplayableMessage.  If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (u *TestUser) SetTableName(n string) {
	u.Table = n
}

// TableName overrides the table name for TestCar
func (c *TestCar) TableName() string {
	if c.Table != "" {
		return c.Table
	}
	return defaultTestCarTableName
}

// SetTableName allows the table name to be overridden and makes a TestCar a ReplayableMessage
func (c *TestCar) SetTableName(n string) {
	c.Table = n
}

// TableName overrids the table name for TestRental
func (r *TestRental) TableName() string {
	if r.Table != "" {
		return r.Table
	}
	return defaultTestRentalTableName
}

// SetTableName allows the table name to be overridden and makes a TestRental a ReplayableMessage
func (r *TestRental) SetTableName(n string) {
	r.Table = n
}
