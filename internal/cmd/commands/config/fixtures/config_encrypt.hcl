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
  key ="{{encrypt(eb78KqCwowELYnkOOko/XYz01q1ax3g76J1vCAvt5dQ=)}}"
}

kms "aead" {
  purpose = "worker"
  aead_type = "aes-gcm"
  key ="{{encrypt(aA1hxJo0JUAqcIATx/r0QTjAGD/btCPechEsukI2bt0=)}}"
}
