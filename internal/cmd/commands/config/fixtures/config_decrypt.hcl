# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

kms "aead" {
  purpose = "config"
  aead_type = "aes-gcm"
  key = "c964AJj8VW8w4hKz/Jd8MvuLt0kkcjVuFqMiMvTvvN8="
}

kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key ="{{decrypt(CkgsDUoQ7B5JhE1ye2yVAm3Ss_KNbLQgBhKtibtGSvpGOrwQ3zRTF_qoHPHX-xuqLyZ9zsb3cMo6OpphKOj7AeTn1_iiqZ_VaCsqAA)}}"
}

kms "aead" {
  purpose = "worker"
  aead_type = "aes-gcm"
  key ="{{decrypt(CkiRTINwX19TnC3AB-zx5E133TXI9KzBWb8TxfVDrPb9m3Yfm9K99OkuJgRTj1rjmeMF-Kpl-0oouEc8_mNk6oPIqD8nUNvH3FYqAA)}}"
}
