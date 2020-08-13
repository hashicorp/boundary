begin;

  drop table host_set;
  drop table host;
  drop table host_catalog;

  delete
    from oplog_ticket
   where name in (
          'host_catalog',
          'host',
          'host_set'
        );

commit;
