begin;
  alter table host_plugin_catalog_secret (
    add column ttl wt_timestamp;
  );
commit;

