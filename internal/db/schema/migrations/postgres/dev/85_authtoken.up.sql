begin;

-- auth_token_status_enm entries define the possible auth token
-- states. 
create table auth_token_status_enm (
  name text primary key
    constraint only_predefined_auth_token_states_allowed
    check (
        name in ('auth token pending','token issued', 'authentication failed', 'system error')
    )
);

-- populate the values of auth_token_status_enm
insert into auth_token_status_enm(name)
  values
    ('auth token pending'),
    ('token issued'),
    ('authentication failed'),
    ('system error'); 


-- add the state column with a default to the auth_token table.
alter table auth_token
add column status text 
not null
default 'token issued' -- safest default
references auth_token_status_enm(name);

commit;