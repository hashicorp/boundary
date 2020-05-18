BEGIN;

CREATE OR REPLACE FUNCTION update_time_column() RETURNS TRIGGER 
SET SCHEMA
  'public' LANGUAGE plpgsql AS $$
BEGIN
   IF row(NEW.*) IS DISTINCT FROM row(OLD.*) THEN
      NEW.update_time = now(); 
      RETURN NEW;
   ELSE
      RETURN OLD;
   END IF;
END;
$$;

CREATE TABLE iam_scope_type_enm (
  string text NOT NULL primary key CHECK(string IN ('unknown', 'organization', 'project'))
);
INSERT INTO iam_scope_type_enm (string)
values
  ('unknown'),
  ('organization'),
  ('project');

 
CREATE TABLE iam_scope (
    public_id wt_public_id primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
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
    description text,
    parent_id text REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE
  );
create table iam_scope_organization (
    scope_id wt_public_id NOT NULL UNIQUE REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    name text UNIQUE,
    primary key(scope_id)
  );
create table iam_scope_project (
    scope_id wt_public_id NOT NULL REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    parent_id wt_public_id NOT NULL REFERENCES iam_scope_organization(scope_id) ON DELETE CASCADE ON UPDATE CASCADE,
    name text,
    unique(parent_id, name),
    primary key(scope_id, parent_id)
  );


CREATE
  OR REPLACE FUNCTION iam_sub_scopes_func() RETURNS TRIGGER
SET SCHEMA
  'public' LANGUAGE plpgsql AS $$ DECLARE parent_type INT;
BEGIN IF new.type = 'organization' THEN
insert into iam_scope_organization (scope_id, name)
values
  (new.public_id, new.name);
return NEW;
END IF;
IF new.type = 'project' THEN
insert into iam_scope_project (scope_id, parent_id, name)
values
  (new.public_id, new.parent_id, new.name);
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

CREATE TRIGGER update_iam_scope_update_time 
BEFORE 
UPDATE ON iam_scope FOR EACH ROW EXECUTE PROCEDURE update_time_column();

CREATE TABLE iam_user (
    public_id wt_public_id not null primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_public_id NOT NULL REFERENCES iam_scope_organization(scope_id) ON DELETE CASCADE ON UPDATE CASCADE,
    unique(name, scope_id),
    disabled BOOLEAN NOT NULL default FALSE
  );

CREATE TRIGGER update_iam_group_update_time 
BEFORE 
UPDATE ON iam_user FOR EACH ROW EXECUTE PROCEDURE update_time_column();

COMMIT;
