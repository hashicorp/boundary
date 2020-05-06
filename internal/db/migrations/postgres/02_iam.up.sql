BEGIN;

CREATE TABLE if not exists iam_scope_type_enm (
  string text NOT NULL primary key CHECK(string IN ('unknown', 'organization', 'project'))
);
INSERT INTO iam_scope_type_enm (string)
values
  ('unknown'),
  ('organization'),
  ('project');

 
CREATE TABLE if not exists iam_scope (
    public_id text NOT NULL primary key,
    create_time timestamp with time zone default current_timestamp,
    update_time timestamp with time zone default current_timestamp,
    name text UNIQUE,
    type text NOT NULL REFERENCES iam_scope_type_enm(string) CHECK(
      (
        type = 'organization'
        and parent_id = NULL
      )
      or (
        type = 'project'
        and parent_id IS NOT NULL
      )
    ),
    parent_id text REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    disabled BOOLEAN NOT NULL default FALSE
  );
create table if not exists iam_scope_organization (
    scope_id text NOT NULL UNIQUE REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE
  );
create table if not exists iam_scope_project (
    scope_id text REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    parent_id text REFERENCES iam_scope_organization(scope_id) ON DELETE CASCADE ON UPDATE CASCADE
  );


CREATE
  OR REPLACE FUNCTION iam_sub_scopes_func() RETURNS TRIGGER
SET SCHEMA
  'public' LANGUAGE plpgsql AS $$ DECLARE parent_type INT;
BEGIN IF new.type = 'organization' THEN
insert into iam_scope_organization (scope_id)
values
  (new.public_id);
return NEW;
END IF;
IF new.type = 'project' THEN
insert into iam_scope_project (scope_id, parent_id)
values
  (new.public_id, new.parent_id);
return NEW;
END IF;
RAISE EXCEPTION 'unknown scope type';
END;
$$;


CREATE TRIGGER iam_scope_insert
AFTER
insert ON iam_scope FOR EACH ROW EXECUTE PROCEDURE iam_sub_scopes_func();


CREATE
  OR REPLACE FUNCTION iam_immutable_scope_type_func() RETURNS TRIGGER
SET SCHEMA
  'public' LANGUAGE plpgsql AS $$ DECLARE parent_type INT;
BEGIN IF new.type != old.type THEN
RAISE EXCEPTION 'scope type cannot be updated';
END IF;
return NEW;
END;
$$;

CREATE TRIGGER iam_scope_update
BEFORE
update ON iam_scope FOR EACH ROW EXECUTE PROCEDURE iam_immutable_scope_type_func();

COMMIT;