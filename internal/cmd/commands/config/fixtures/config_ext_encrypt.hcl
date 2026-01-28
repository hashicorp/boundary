# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

int_val = {{encrypt(20)}}
bool_val = {{encrypt(true)}}
kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key ="{{encrypt(aA1hxJo0JUAqcIATx/r0QTjAGD/btCPechEsukI2bt0=)}}"
}