begin;

drop table target cascade;
drop table target_host_set cascade;
drop table target_tcp;


delete
from oplog_ticket
where name in (
        'target_tcp'
    );

commit;