begin;

drop table kms_key_entry_purpose_enm cascade;
drop table kms_external_config cascade;
drop table kms_root_key cascade;
drop table kms_root_key_version cascade;
drop table kms_database_key cascade;
drop table kms_database_key_version cascade;
drop table kms_oplog_key cascade;
drop table kms_oplog_key_version cascade;
drop table kms_session_key cascade;
drop table kms_session_key_version cascade;
drop function kms_scope_valid() cascade;

commit;
