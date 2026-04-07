schema_version = 1

project {
  license        = "MPL-2.0"
  copyright_year = 2024
  ignore_year1 = true # required to preserve existing start years

  # Ignore all auto-generated protobuf and go-generate files
  header_ignore = [
    "**/*.gen.go",
    "**/*.pb.go",
    "**/*.pb.gw.go"
  ]
}
