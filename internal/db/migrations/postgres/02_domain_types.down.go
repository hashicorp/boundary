package postgres

const DomainTypesDown02 = `
begin;

drop domain wt_public_id;

commit;
`
