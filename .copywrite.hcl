schema_version = 1

project {
  license        = "BUSL-1.1"
  copyright_year = 2024

  header_ignore = [
    ".github/**",
    ".golangci.yml",
    ".release/linux/**",
    "enos/.enos/**",
    "internal/ui/.tmp/**",
    "website/.eslintrc.js",
    "website/prettier.config.js",
    "**/*_ent.*",
    "**/*_ent_test.*",

    # licensed under MPL - ignoring for now until the copywrite tool can support
    # multiple licenses per repo.
    "api/**",
    "sdk/**",
    "internal/proto/plugin/**",
    "internal/proto/controller/custom_options/**", 
    "internal/proto/controller/api/**",
    "internal/proto/worker/proxy/v1/**",
  ]
}
