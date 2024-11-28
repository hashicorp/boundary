# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

container {
	dependencies = true
	alpine_secdb = true
	secrets      = false

	triage {
    	    suppress {
    	        // Suppress wget vulnerability
    	        vulnerabilities = ["CVE-2024-10524"]
    	    }
    	}
}

binary {
	secrets      = true
	go_modules   = true
	osv          = true
	oss_index    = true
	nvd          = true
}
