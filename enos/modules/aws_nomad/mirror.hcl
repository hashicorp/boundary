plugin_cache_dir = "$PWD/terraform-plugin-cache"

provider_installation {
  network_mirror {
    url = "https://enos-provider-current.s3.amazonaws.com/"
    include = ["hashicorp.com/qti/enos"]
  }
  direct {
    exclude = [
      "hashicorp.com/qti/enos"
    ]
  }
}
