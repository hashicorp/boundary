-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

alter table plugin add column description text;
alter table plugin add column create_time wt_timestamp;
alter table plugin add column update_time wt_timestamp;
alter table plugin add column version wt_version;

update plugin as p
set description = ph.description,
    create_time = ph.create_time,
    update_time = ph.update_time,
    version = ph.version
from plugin_host as ph
where p.public_id = ph.public_id;

-- create new triggers on plugin
create trigger update_version_column after update on plugin
  for each row execute procedure update_version_column();

create trigger update_time_column before update on plugin
  for each row execute procedure update_time_column();

create trigger default_create_time_column before insert on plugin
  for each row execute procedure default_create_time();

drop trigger immutable_columns on plugin;
create trigger immutable_columns before update on plugin
  for each row execute procedure immutable_columns('public_id', 'create_time');

drop trigger insert_plugin_subtype on plugin_host;
drop trigger update_plugin_subtype on plugin_host;
drop trigger delete_plugin_subtype on plugin_host;

create table plugin_host_supported (
  public_id wt_plugin_id primary key
    references plugin(public_id)
    on delete cascade
    on update cascade
);
comment on table plugin_host_supported is
  'plugin_storage_supported entries indicate that a given plugin is flagged as a host plugin.';

-- flag all existing host plugins as being host plugins
insert into plugin_host_supported
(public_id)
select public_id
from plugin_host;

-- drop existing references to plugin_host, remake to plugin
alter table host_plugin_catalog
drop constraint plugin_host_fkey;

alter table host_plugin_catalog
  add constraint plugin_host_supported_fkey
    foreign key (plugin_id)
    references plugin_host_supported (public_id)
    on delete cascade
    on update cascade;

-- create a comment for host_plugin_catalog since it doesn't exist yet
comment on table host_plugin_catalog is
  'host_plugin_catalog joins host catalogs to the host plugin that manage them.';

drop table plugin_host;

commit;
