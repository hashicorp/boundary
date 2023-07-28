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
    exclude = ["testing", "website"]
    config = ["p/r2c-security-audit"]
    exclude_rule = ["generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var"]
  }
  
  # plugin "codeql" {
  #  languages = ["go"]
  # }
}
