begin;
-- First create 30 orgs
  with org_ids (public_id, num) as (
    select 'o__________' ||o, o
      from generate_series(1, 30) o
  )
  insert into iam_scope
              (parent_id, type,  public_id,  description, name)
       select 'global',   'org', public_id,  num,         'Organization ' || public_id
         from org_ids;

 -- Then create 50 projects per org, for a total of 1500 projects.
 with p (num) as (
   select generate_series(1, 50) as num
 ) ,
 orgs (public_id, description) as (
  select public_id, description
    from iam_scope
   where type = 'org'
 ),
 project_ids (org_id, org_num, public_id, num) as (
   select org.public_id                                 as org_id,
          org.description                               as org_num,
          'p______o' || org.description || '_' || p.num as public_id,
          p.num                                         as num
     from p,
          orgs as org
 )
 insert into iam_scope
              (parent_id, type,      public_id,  description,           name)
       select org_id,     'project', public_id,  org_num || '_' || num, 'Project ' || public_id
         from project_ids;



-- Insert into kms_root_key table for all scopes including global
insert into kms_root_key
            (private_id, scope_id)
     select 'root_key_' || public_id, public_id
       from iam_scope
      where type in ('global', 'org', 'project');

-- Insert into kms_root_key_version table for all root keys including global
insert into kms_root_key_version
            (private_id, root_key_id, version, key)
    select 'root_key_version_' || public_id, 'root_key_' || public_id, 1,
            decode('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789', 'hex')
      from iam_scope
     where type in ('global', 'org', 'project');

-- Insert into kms_data_key table for all root keys including global
insert into kms_data_key (private_id, root_key_id, purpose)
select 'data_key_' || public_id, 'root_key_' || public_id, 'encryption'
  from iam_scope
  where type in ('global', 'org', 'project');

-- Insert into kms_data_key_version table for all data keys and root key versions including global
insert into kms_data_key_version (private_id, root_key_version_id, data_key_id, version, key)
select 'kms_key_id_' || public_id,
        'root_key_version_' || public_id,
        'data_key_' || public_id,
        1,
        decode('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex')
  from iam_scope
  where type in ('global', 'org', 'project');

commit;
