begin;

drop table auth_token_status_enm;
alter table auth_token drop column status;


commit;
