-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

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
