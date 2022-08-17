begin;

  alter table server_worker
    add column release_version text;

commit;