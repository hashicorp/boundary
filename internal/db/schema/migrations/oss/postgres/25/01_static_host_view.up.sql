-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- static_host_with_set_memberships is used for associating a static host instance with all its related host sets
-- in the set_ids column. Currently there are no size limits.
create view static_host_with_set_memberships as
select
  h.public_id,
  h.create_time,
  h.update_time,
  h.name,
  h.description,
  h.catalog_id,
  h.address,
  h.version,
  -- the string_agg(..) column will be null if there are no associated value objects
  string_agg(distinct hsm.set_id, '|') as set_ids
from
  static_host h
    left outer join static_host_set_member hsm on h.public_id = hsm.host_id
group by h.public_id;
comment on view static_host_with_set_memberships is
  'static host with its associated host sets';

commit;