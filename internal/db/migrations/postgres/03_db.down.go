package postgres

const DbDown03 = `
drop table if exists db_test_user;
drop table if exists db_test_car;
drop table if exists db_test_rental;
`
