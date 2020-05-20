begin;

drop table if exists db_test_user;
drop table if exists db_test_car;
drop table if exists db_test_rental;

drop trigger if exists update_db_test_user_update_time on db_test_user;
drop trigger if exists update_db_test_user_create_time on db_test_user;

drop trigger if exists update_db_test_car_update_time on db_test_car;
drop trigger if exists update_db_test_car_create_time on db_test_car;

drop trigger if exists update_db_test_rental_update_time on db_test_rental;
drop trigger if exists update_db_test_rental_create_time on db_test_rental;

commit;
