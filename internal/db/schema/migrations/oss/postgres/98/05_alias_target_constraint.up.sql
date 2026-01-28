-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Updates 85/04_alias_target.up.sql to add a unique constraint on the public id and destination id
alter table alias_target
    add constraint alias_target_destination_uq unique (public_id, destination_id);

commit;