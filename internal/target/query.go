package target

const (
	setChangesQuery = `
with
set_libraries (library_id) as (
  -- returns the SET list
  select public_id
    from credential_library
   where public_id in (%s)
),
current_libraries (library_id) as (
  -- returns the current list
  select credential_library_id
    from target_credential_library
   where target_id = @target_id
),
keep_libraries (library_id) as (
  -- returns the KEEP list
  select library_id
    from current_libraries
   where library_id in (select * from set_libraries)
),
delete_libraries (library_id) as (
  -- returns the DELETE list
  select library_id
    from current_libraries
   where library_id not in (select * from set_libraries)
),
insert_libraries (library_id) as (
  -- returns the ADD list
  select library_id
    from set_libraries
   where library_id not in (select * from keep_libraries)
),
final (action, library_id) as (
  select 'delete', library_id
    from delete_libraries
   union
  select 'add', library_id
    from insert_libraries
)
select * from final
order by action, library_id;
`
)
