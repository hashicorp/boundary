-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Remove invalid (states with no prior end time) rows
delete from session_state where previous_end_time is null and state != 'pending';

-- In the case of dupes that are otherwise valid, identify first valid session state and remove others
with cte_session_state_delete
         as (select session_id, min(start_time) as st_t, state from session_state ou
             where (select count(*) from session_state inr
                    where inr.session_id = ou.session_id and inr.state = ou.state) > 1
             group by session_id, state)
delete from session_state t1
    using cte_session_state_delete t2 where t1.session_id =t2.session_id and t1.start_time > t2.st_t and t1.state=t2.state;

-- Close all open session_connections
update session_connection
set closed_reason='canceled' where closed_reason is null;

update session
set termination_reason='canceled' where termination_reason is null;

-- End of data cleanup; start of table modifications

-- session_valid_state table creation and related constraints
create table session_valid_state(
    prior_state text
        references session_state_enm(name)
            on delete restrict
            on update cascade,
        constraint prior_state_session_state_enm_fkey
        check (
                prior_state in ('pending', 'active', 'canceling')
            ),
    current_state text
        references session_state_enm(name)
            on delete restrict
            on update cascade,
        constraint current_state_session_state_enm_fkey
        check (
            current_state in ('pending', 'active', 'canceling', 'terminated')
        ),
    primary key (prior_state, current_state)
);
comment on table session_valid_state is
  'session_valid_state entries define valid prior_state and current_state pairs to define valid state transitions';

insert into session_valid_state (prior_state, current_state)
values
    ('pending','pending'),
    ('pending','active'),
    ('pending','terminated'),
    ('pending','canceling'),
    ('active','canceling'),
    ('active','terminated'),
    ('canceling','terminated');

alter table session_state
    add column prior_state text not null default 'pending'
        references session_state_enm(name)
        on delete restrict
        on update cascade;
alter table session_state
    add constraint session_valid_state_enm_fkey
        foreign key (prior_state, state)
        references session_valid_state (prior_state,current_state);
alter table session_state
    add unique (session_id, state);

create function update_prior_session_state() returns trigger
as $$
begin
    -- Prior state is the most recent valid prior state entry for this session_id
    new.prior_state = query.state from(
      select state from session_state where session_id=new.session_id and state in(
          select prior_state from session_valid_state where current_state=new.state )
      order by start_time desc limit 1) as query;

    if new.prior_state is null then
        new.prior_state='pending';
    end if;

    return new;

end;
$$ language plpgsql;

create trigger update_session_state before insert on session_state
    for each row execute procedure update_prior_session_state();

commit;
