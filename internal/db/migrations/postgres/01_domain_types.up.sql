begin;

create domain wt_public_id as text
check(
  length(trim(value)) > 10
);
comment on domain wt_public_id is
'Random ID generated with github.com/hashicorp/vault/sdk/helper/base62';

create domain wt_timestamp as
  timestamp with time zone
  default current_timestamp;
comment on domain wt_timestamp is
'Standard timestamp for all create_time and update_time columns';


CREATE OR REPLACE FUNCTION update_time_column() RETURNS TRIGGER 
LANGUAGE plpgsql AS $$
BEGIN
   IF row(NEW.*) IS DISTINCT FROM row(OLD.*) THEN
      NEW.update_time = now(); 
      RETURN NEW;
   ELSE
      RETURN OLD;
   END IF;
END;
$$;
comment on function update_time_column() is
'function used in before update triggers to properly set update_time columns';

CREATE
  OR REPLACE FUNCTION immutable_create_time_func() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN IF NEW.create_time IS DISTINCT FROM OLD.create_time THEN
NEW.create_time = OLD.create_time;
RAISE WARNING 'create_time cannot be set to %', new.create_time;
END IF;
return NEW;
END;
$$;
comment on function immutable_create_time_func() is
'function used in before update triggers to make create_time column immutable';

commit;
