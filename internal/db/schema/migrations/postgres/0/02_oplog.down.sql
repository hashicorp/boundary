begin;

drop table oplog_metadata cascade;
drop table oplog_ticket cascade;
drop table oplog_entry cascade;

commit;
