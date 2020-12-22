begin;

  drop table static_host_set_member cascade;
  drop table static_host_set cascade;
  drop table static_host cascade;
  drop table static_host_catalog cascade;

  delete
    from oplog_ticket
   where name in (
          'static_host_catalog',
          'static_host',
          'static_host_set',
          'static_host_set_member'
        );

commit;
