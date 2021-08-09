-- session_multiple_sessions tests the wh_credential_dimension when
-- multiple sessions are created using.
begin;
  select plan(6);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- insert first session, should result in a new credentials dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');

  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  -- should not result in a new credential dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's2____walter');

  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- change the crediential for the target
  update credential_vault_library set vault_path = '/secrets/tcp/admin';

  -- start another session, should result in a new credential dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's3____walter');
  select is(count(*), 2::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- add a credential to the target
  insert into credential_vault_library
    (store_id,       public_id,     name,                   description, vault_path, http_method)
  values
    ('vs_______wvs', 'vl_____wvl2', 'widget vault ssh', 'None',      '/secrets/ssh/admin', 'GET');

  insert into target_credential_library
    (target_id,      credential_library_id, credential_purpose)
  values
    ('t_________wb', 'vl_____wvl2',         'application');

  -- start another session, should result in a two new credential dimensions
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's4____walter');
  select is(count(*), 4::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- change the crediential again for the target
  update credential_vault_library set vault_path = '/secrets/tcp/user' where vault_path = '/secrets/tcp/admin';

  -- start another session, should result in a two new credential dimensions since one changes, and it will create a new group
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's5____walter');
  select is(count(*), 6::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  select * from finish();
rollback;
