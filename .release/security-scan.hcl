container {
	dependencies = false
	alpine_secdb = true
	secrets      = false
}

binary {
	secrets      = true
	go_modules   = true
	osv          = false
	oss_index    = true
	nvd          = true
}