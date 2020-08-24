begin;

drop table target cascade;
drop table target_host_set cascade;
drop table target_tcp;
drop view target_all_subtypes;
drop view target_host_set_catalog;


delete
from oplog_ticket
where name in (
        'target_tcp'
    );

commit;