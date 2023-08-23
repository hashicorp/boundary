# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

int_val = {{encrypt(20)}}
bool_val = {{encrypt(true)}}
kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key ="{{encrypt(aA1hxJo0JUAqcIATx/r0QTjAGD/btCPechEsukI2bt0=)}}"
}