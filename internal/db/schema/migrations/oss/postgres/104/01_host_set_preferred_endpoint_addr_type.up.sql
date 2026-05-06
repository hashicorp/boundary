-- Copyright IBM Corp. 2026
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Replaces condition_has_valid_prefix from 20/05_plugin_host.up.sql
  -- to also accept 'address_type:' as a valid prefix.
  alter table host_set_preferred_endpoint
    drop constraint condition_has_valid_prefix;

  alter table host_set_preferred_endpoint
    add constraint condition_has_valid_prefix
      check(
            left(trim(condition), 4) = 'dns:'
          or
            left(trim(condition), 5) = 'cidr:'
          or
            left(trim(condition), 13) = 'address_type:'
        );

commit;
