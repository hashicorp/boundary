# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

container {
	dependencies = true
	alpine_secdb = true
	secrets      = false

	# Triage items that are _safe_ to ignore here. Note that this list should be
	# periodically cleaned up to remove items that are no longer found by the scanner.
	triage {
		suppress {
			vulnerabilities = [
				# busybox@1.37.0-r12 https://nvd.nist.gov/vuln/detail/CVE-2025-46394
				#
				# Boundary does not shell out to the busybox tar program.
				"CVE-2025-46394",

				# busybox@1.37.0-r12 https://nvd.nist.gov/vuln/detail/CVE-2024-58251
				#
				# Boundary does not shell out to the busybox netstat program.
				"CVE-2024-58251",

				# gnupg@2.4.7-r0 https://nvd.nist.gov/vuln/detail/CVE-2025-30258
				#
				# Boundary does not utilize GnuPG to import certificates.
				"CVE-2025-30258",

				# iputils@20240905-r0 https://nvd.nist.gov/vuln/detail/CVE-2025-47268
				#
				# Boundary does not utilize ping in iputils.
				"CVE-2025-47268",

				# iputils@20240905-r0 https://nvd.nist.gov/vuln/detail/CVE-2025-48964
				#
				# Boundary does not utilize ping in iputils.
				"CVE-2025-48964"
			]
		}
	}
}

binary {
	secrets      = true
	go_modules   = true
	osv          = true
	oss_index    = true
	nvd          = true

	# Triage items that are _safe_ to ignore here. Note that this list should be
	# periodically cleaned up to remove items that are no longer found by the scanner.
	triage {
		suppress {
			vulnerabilities = [
				"GO-2025-3408", # yamux@v0.1.1
				"GHSA-29qp-crvh-w22m", # yamux@v0.1.1
			]
		}
	}
}
