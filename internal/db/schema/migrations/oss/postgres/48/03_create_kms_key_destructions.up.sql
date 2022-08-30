begin;

  create table kms_key_destruction_status_enm (
    name text primary key
      constraint only_predefined_values_allowed
      check(name in ('pending', 'running', 'completed', 'failed'))
  );
  comment on table kms_key_destruction_status_enm is
    'Table holding valid statuses a key destruction can take';

  insert into kms_key_destruction_status_enm (name)
  values
    ('pending'),
    ('running'),
    ('completed'),
    ('failed');

  create trigger 
    immutable_columns
  before
  update on kms_key_destruction_status_enm
    for each row execute procedure immutable_columns('name');

  create table kms_key_destruction (
    private_id wt_private_id primary key,
    key_id wt_private_id not null, -- Note: not a foreign key, outlives original reference
    activation_time wt_timestamp not null,
    deactivation_time wt_timestamp not null,
    destruction_start_time wt_timestamp not null,
    destruction_end_time wt_timestamp null default null,
    status text not null
      references kms_key_destruction_status_enm(name)
  );
  comment on table kms_key_destruction is
    'Table holding historical, current and pending key destructions';

  create trigger immutable_columns before update on kms_key_destruction
    for each row execute procedure immutable_columns('private_id', 'key_id', 'activation_time', 'deactivation_time', 'destruction_start_time');

commit;
