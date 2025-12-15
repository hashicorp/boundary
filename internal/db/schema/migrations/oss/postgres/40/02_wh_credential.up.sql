-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- update egress to injected_application
  update wh_credential_dimension
     set credential_purpose = 'injected_application'
   where credential_purpose = 'egress';

  -- update application to brokered
  update wh_credential_dimension
     set credential_purpose = 'brokered'
   where credential_purpose = 'application';

commit;
