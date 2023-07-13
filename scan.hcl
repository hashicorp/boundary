# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

repository {
  go_modules = true
  # osv = true
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
    config = ["p/gosec"]
  }
  
  plugin "codeql" {
    languages = ["go"]
   }
}
