// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hook46001

const (
	baseQuery = `
      with
      targets (target_id, target_project_id, target_org_id) as (
        select t.public_id, t.project_id, prj.parent_id
          from target            as t
          join iam_scope_project as prj on t.project_id = prj.scope_id
      ),
      libraries (library_id, library_store_id, library_project_id, library_org_id) as (
        select cl.public_id, cs.public_id, cs.project_id, prj.parent_id
          from credential_library as cl
          join credential_store   as cs  on cl.store_id   = cs.public_id
          join iam_scope_project  as prj on cs.project_id = prj.scope_id
      ),
      bad_libraries (target_id, target_project_id, target_org_id,
                     library_id, library_store_id, library_project_id, library_org_id) as (
        select tt.target_id, tt.target_project_id, tt.target_org_id,
               ll.library_id, ll.library_store_id, ll.library_project_id, ll.library_org_id
          from target_credential_library as tcl
          join targets                   as tt on tcl.target_id             = tt.target_id
          join libraries                 as ll on tcl.credential_library_id = ll.library_id
         where tt.target_project_id <> ll.library_project_id
      ),
      credentials (credential_id, credential_store_id, credential_project_id, credential_org_id) as (
        select cc.public_id, cs.public_id, cs.project_id, prj.parent_id
          from credential_static  as cc
          join credential_store   as cs  on cc.store_id   = cs.public_id
          join iam_scope_project  as prj on cs.project_id = prj.scope_id
      ),
      bad_credentials (target_id, target_project_id, target_org_id,
                       credential_id, credential_store_id, credential_project_id, credential_org_id) as (
        select tt.target_id, tt.target_project_id, tt.target_org_id,
               cc.credential_id, cc.credential_store_id, cc.credential_project_id, cc.credential_org_id
          from target_static_credential as tsc
          join targets                  as tt on tsc.target_id            = tt.target_id
          join credentials              as cc on tsc.credential_static_id = cc.credential_id
         where tt.target_project_id <> cc.credential_project_id
      ),
      host_sets (host_set_id, host_set_catalog_id, host_set_project_id, host_set_org_id) as (
        select hs.public_id, hc.public_id, hc.project_id, prj.parent_id
          from host_set          as hs
          join host_catalog      as hc  on hs.catalog_id = hc.public_id
          join iam_scope_project as prj on hc.project_id = prj.scope_id
      ),
      bad_host_sets (target_id, target_project_id, target_org_id,
                     host_set_id, host_set_catalog_id, host_set_project_id, host_set_org_id) as (
        select tt.target_id, tt.target_project_id, tt.target_org_id,
               hh.host_set_id, hh.host_set_catalog_id, hh.host_set_project_id, hh.host_set_org_id
          from target_host_set as ths
          join targets         as tt on ths.target_id   = tt.target_id
          join host_sets       as hh on ths.host_set_id = hh.host_set_id
         where tt.target_project_id <> hh.host_set_project_id
      ),
      problems (resource_type, target_id, target_project_id, target_org_id,
                resource_id, resource_parent_id, resource_project_id, resource_org_id) as (
        select 'credential library', target_id, target_project_id, target_org_id,
               library_id, library_store_id, library_project_id, library_org_id
          from bad_libraries
         union
        select 'static credential', target_id, target_project_id, target_org_id,
               credential_id, credential_store_id, credential_project_id, credential_org_id
          from bad_credentials
         union
        select 'host set', target_id, target_project_id, target_org_id,
               host_set_id, host_set_catalog_id, host_set_project_id, host_set_org_id
          from bad_host_sets
      )`

	getIllegalAssociationsQuery = baseQuery + `
		select * from problems;
	`

	deleteIllegalAssociationsQuery = baseQuery + `,
      deleted_libraries (target_id, library_id) as (
           delete
             from target_credential_library
            where (target_id, credential_library_id) in (select target_id, library_id from bad_libraries)
        returning target_id, credential_library_id
      ),
      deleted_credentials (target_id, credential_id) as (
           delete
             from target_static_credential
            where (target_id, credential_static_id) in (select target_id, credential_id from bad_credentials)
        returning target_id, credential_static_id
      ),
      deleted_host_sets(target_id, host_set_id) as (
           delete
             from target_host_set
            where (target_id, host_set_id) in (select target_id, host_set_id from bad_host_sets)
        returning target_id, host_set_id
      ),
      deleted_problems (resource_type, target_id, target_project_id, target_org_id,
                        resource_id, resource_parent_id, resource_project_id, resource_org_id) as (
        select resource_type, target_id, target_project_id, target_org_id,
               resource_id, resource_parent_id, resource_project_id, resource_org_id
          from problems
         where (target_id, resource_id) in (select target_id, library_id    from deleted_libraries)
            or (target_id, resource_id) in (select target_id, credential_id from deleted_credentials)
            or (target_id, resource_id) in (select target_id, host_set_id   from deleted_host_sets)
      )
      select * from deleted_problems;`
)
