begin;

create domain icu_public_id as text
check(
  length(trim(value)) > 31
);
comment on domain icu_public_id is
'Random ID generated with github.com/hashicorp/vault/sdk/helper/base62';

commit;
