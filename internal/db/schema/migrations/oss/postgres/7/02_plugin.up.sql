-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

    create domain wt_plugin_id as text not null
      check(
        length(trim(value)) > 10 or value = 'pi_system'
      );
    comment on domain wt_plugin_id is
      '"pi_system", or random ID generated with github.com/hashicorp/go-secure-stdlib/base62';

    create table plugin (
      public_id wt_plugin_id primary key
    );
    comment on table plugin is
      'plugin is a table where each row represents a unique plugin registered with Boundary.';

    insert into plugin (public_id)
      values
      ('pi_system');

    create trigger immutable_columns before update on plugin
      for each row execute procedure immutable_columns('public_id');

    create or replace function disallow_system_plugin_deletion() returns trigger
    as $$
    begin
      if old.public_id = 'pi_system' then
        raise exception 'deletion of system plugin not allowed';
      end if;
      return old;
    end;
    $$ language plpgsql;

    create trigger plugin_disallow_system_deletion before delete on plugin
      for each row execute procedure disallow_system_plugin_deletion();

commit;
