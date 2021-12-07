begin;
  alter table host_plugin_catalog_secret (
    add column ttl_seconds int
      constraint ttl_seconds_not_less_than_zero
        check(sync_interval_seconds >= 0)
  );
commit;
