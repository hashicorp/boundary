package oplog_test

import "github.com/jinzhu/gorm"

func Init(db *gorm.DB) {
	db.AutoMigrate(&TestUser{})
	db.AutoMigrate(&TestCar{})
	db.AutoMigrate(&TestRental{})
}
func Reinit(db *gorm.DB) {
	db.DropTableIfExists(&TestUser{})
	db.DropTableIfExists(&TestCar{})
	db.DropTableIfExists(&TestRental{})
	Init(db)
}

func (*TestUser) TableName() string { return "oplog_test_user" }

func (*TestCar) TableName() string { return "oplog_test_car" }

func (*TestRental) TableName() string { return "oplog_test_rental" }
