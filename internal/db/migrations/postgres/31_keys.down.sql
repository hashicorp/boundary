begin;

drop table kms_root_key cascade;
drop table kms_root_key_version cascade;
drop table kms_database_key cascade;
drop table kms_database_key_version cascade;
drop table kms_oplog_key cascade;
drop table kms_oplog_key_version cascade;
drop table kms_session_key cascade;
drop table kms_session_key_version cascade;

commit;
