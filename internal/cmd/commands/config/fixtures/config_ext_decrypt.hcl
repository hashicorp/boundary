# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

int_val = {{decrypt(Ch7a69AX8R5w_cCZJUqLTQkWesuSHMrHxrRMMZnq53QqAA)}}
bool_val = {{decrypt(CiDURLrWUXLhEfkOemqqiQlcD_gsGsIx-kxVTIlVncN6-yoA)}}
kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key ="{{decrypt(CkiRTINwX19TnC3AB-zx5E133TXI9KzBWb8TxfVDrPb9m3Yfm9K99OkuJgRTj1rjmeMF-Kpl-0oouEc8_mNk6oPIqD8nUNvH3FYqAA)}}"
}