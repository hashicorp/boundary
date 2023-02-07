schema_version = 1

project {
  license        = "MPL-2.0"
  copyright_year = 2023

  header_ignore = [
    ".circleci/**",
    ".github/**",
    ".golangci.yml",
    ".release/linux/**",
    "enos/.enos/**",
    "internal/ui/.tmp/**",
    "website/.eslintrc.js",
    "website/prettier.config.js",
  ]
}
