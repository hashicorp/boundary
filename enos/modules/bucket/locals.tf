# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

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
