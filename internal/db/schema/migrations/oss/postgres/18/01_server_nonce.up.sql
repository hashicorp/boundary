begin;

-- This migration exists to generalize the nonce behavior since we need it for
-- more than recovery nonces.

-- Drop existing triggers
drop trigger default_create_time_column on recovery_nonces;
drop trigger immutable_columns on recovery_nonces;

-- Update table name
alter table recovery_nonces rename to server_nonce;

-- Add purpose field and check
alter table server_nonce add column purpose text
  constraint only_predefined_purpose_types_allowed
    check(purpose in ('recovery', 'worker-auth'));

-- Migrate any existing data
update server_nonce set purpose = 'recovery';

-- Now, add not-null
alter table server_nonce
  alter column purpose
    set not null;

-- Recreate triggers
create trigger 
  default_create_time_column
before
insert on server_nonce
  for each row execute procedure default_create_time();

create trigger 
  immutable_columns
before
update on server_nonce
  for each row execute procedure immutable_columns('nonce', 'create_time', 'purpose');

commit;