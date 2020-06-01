begin;

drop table if exists oplog_entry cascade;

drop trigger if exists update_oplog_entry_update_time on oplog_entry;
drop trigger if exists update_oplog_entry_create_time on oplog_entry;

drop table if exists oplog_ticket cascade;

drop trigger if exists update_oplog_ticket_update_time on oplog_ticket;
drop trigger if exists update_oplog_ticket_create_time on oplog_ticket;

drop table if exists oplog_metadata cascade;

drop trigger if exists update_oplog_metadata_update_time on oplog_metadata;
drop trigger if exists update_oplog_metadata_create_time on oplog_metadata;

commit;