begin;

  drop table host_set;
  drop table host;
  drop table host_catalog;

  drop function insert_host_set_subtype;
  drop function insert_host_subtype;
  drop function insert_host_catalog_subtype;

  delete
    from oplog_ticket
   where name in (
          'host_catalog',
          'host',
          'host_set'
        );

commit;
