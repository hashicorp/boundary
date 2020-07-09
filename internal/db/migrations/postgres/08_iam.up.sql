BEGIN;


CREATE TABLE iam_auth_method (
    public_id wt_public_id primary key, 
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_public_id NOT NULL REFERENCES iam_scope_organization(scope_id) ON DELETE CASCADE ON UPDATE CASCADE,
    unique(name, scope_id),
    disabled BOOLEAN NOT NULL default FALSE,
    type text NOT NULL
  );

CREATE TABLE iam_auth_method_type_enm (
    string text primary key CHECK(string IN ('unknown', 'password', 'oidc'))
  );
INSERT INTO iam_auth_method_type_enm (string)
values
  ('unknown'),
  ('password'),
  ('oidc');
ALTER TABLE iam_auth_method
ADD
  FOREIGN KEY (type) REFERENCES iam_auth_method_type_enm(string);

CREATE TABLE iam_action_enm (
    string text primary key CHECK(
      string IN (
        'unknown',
        'list',
        'create',
        'update',
        'read',
        'delete',
        'authenticate',
        'all',
        'connect',
        'add-grants',
        'delete-grants',
        'set-grants'
      )
    )
  );

INSERT INTO iam_action_enm (string)
values
  ('unknown'),
  ('list'),
  ('create'),
  ('update'),
  ('read'),
  ('delete'),
  ('authenticate'),
  ('all'),
  ('connect'),
  ('add-grants'),
  ('delete-grants'),
  ('set-grants');

  COMMIT;
