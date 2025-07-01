// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gorm

import (
	dbassert "github.com/hashicorp/dbassert"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

// TestModel defines a test Gorm model.
type TestModel struct {
	Id       int `gorm:"primary_key"`
	PublicId string
	Nullable *string
	TypeInt  *int
}

// TableName is required by Gorm to define the model's table name when it
// doesn't match the model's Go type name.
func (*TestModel) TableName() string { return "test_table_dbasserts" }

// CreateTestModel is a helper that creates a testModel in the DB.
func CreateTestModel(t dbassert.TestingT, db *gorm.DB, nullable *string, typeInt *int) *TestModel {
	publicId, err := base62.Random(12)
	assert.NoError(t, err)
	m := TestModel{
		PublicId: publicId,
		Nullable: nullable,
		TypeInt:  typeInt,
	}
	err = db.Create(&m).Error
	assert.NoError(t, err)
	return &m
}
