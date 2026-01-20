# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

repository {
  go_modules = true
  osv = true
  secrets {
    all = true
  } 
  dependabot {
    required = true
    check_config = true
  }
  
  plugin "semgrep" {
    use_git_ignore = true
    exclude = ["*_test.go", "website/*", "testing/*"]
    config = ["p/gosec", ".semgrep/"]
  }
  
  plugin "codeql" {
    languages = ["go"]
   }
}
