# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1

locals {
  common_tags = merge(
    var.common_tags,
    {
      Type     = var.cluster_tag
      Module   = "bucket"
      BucketID = random_pet.default.id
    },
  )
}
