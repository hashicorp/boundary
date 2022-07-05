terraform {
  required_version = ">= 1.0"

  required_providers {
    enos = {
      version = ">= 0.1.22"
      source  = "hashicorp.com/qti/enos"
    }
  }
}

variable "path" {
  default = "/tmp"
}

resource "enos_local_exec" "build" {
  environment = {
    "GOOS"          = "linux",
    "GOARCH"        = "amd64",
    "CGO_ENABLED"   = 0,
    "ARTIFACT_PATH" = var.path
  }
  scripts = ["${path.module}/templates/build.sh"]
}

output "artifact_path" {
  value = "${var.path}/boundary.zip"
}
