-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- server table inserts/updates historically included setting the update_time
-- column to now().  Since we're now using the "standard" db package to do this,
-- we need to add triggers to set the update_time for every insert/update.
create trigger update_time_column before update on server
  for each row execute procedure update_time_column();

create trigger insert_time_column before insert on server
  for each row execute procedure update_time_column();

commit;
