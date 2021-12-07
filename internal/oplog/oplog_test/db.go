// Package oplog_test provides some gorm helper funcs for testing oplog database integrations
package oplog_test

import (
	"context"
	"testing"

	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/require"
)

const (
	defaultTestUserTableName   = "oplog_test_user"
	defaultTestCarTableName    = "oplog_test_car"
	defaultTestRentalTableName = "oplog_test_rental"
)

// Init will use gorm migrations to init tables for test models
func Init(t *testing.T, db *dbw.DB) {

	const testQueryCreateTables = `	
	begin;
	
	-- create test tables used in the unit tests for the oplog package 
	-- these tables (oplog_test_user, oplog_test_car, oplog_test_rental) are
	-- not part of the boundary domain model... they are simply used for testing
	-- the oplog package 
	create table if not exists oplog_test_user (
	  -- id bigint generated always as identity primary key,
	  id bigserial primary key,
	  name text,
	  phone_number text,
	  email text
	);
	
	create table if not exists oplog_test_car (
	--   id bigint generated always as identity primary key,
	  id bigserial primary key,
	  name text unique,
	  model text,
	  mpg smallint
	);
	
	create table if not exists oplog_test_rental (
	  user_id bigint not null references oplog_test_user(id),
	  car_id bigint not null references oplog_test_car(id)
	);
	
	  
	commit;
	`
	_, err := dbw.New(db).Exec(context.Background(), testQueryCreateTables, nil)
	require.NoError(t, err)
}

// Reinit will use gorm to drop then init tables for test models
func Reinit(t *testing.T, db *dbw.DB) {
	const sql = ``
	_, err := dbw.New(db).Exec(context.Background(), sql, nil)
	require.NoError(t, err)
	Init(t, db)
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
