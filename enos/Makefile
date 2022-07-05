default: run

generate: fresh-install-generate
validate: fresh-install-validate
launch: fresh-install-launch
run: fresh-install-run
output: fresh-install-output
destroy: fresh-install-destroy

fresh-install-generate:
	enos scenario generate --chdir=./fresh-install

fresh-install-validate:
	export ENOS_VAR_local_boundary_dir="${GOPATH}/bin" &&\
	export ENOS_VAR_enos_user=${USER} &&\
	enos scenario validate --chdir=./fresh-install

fresh-install-launch:
	export ENOS_VAR_local_boundary_dir="${GOPATH}/bin" &&\
	export ENOS_VAR_enos_user=${USER} &&\
	enos scenario launch --chdir=./fresh-install || enos scenario run --chdir=./fresh-install
	# Re-run the terraform apply again if first apply fails due to transient errors

fresh-install-run:
	export ENOS_VAR_local_boundary_dir="${GOPATH}/bin" &&\
	export ENOS_VAR_enos_user=${USER} &&\
	enos scenario run --chdir=./fresh-install || enos scenario run --chdir=./fresh-install
	# Re-run the terraform apply again if first apply fails due to transient errors

fresh-install-output:
	export ENOS_VAR_local_boundary_dir="${GOPATH}/bin" &&\
	export ENOS_VAR_enos_user=${USER} &&\
	enos scenario output --chdir=./fresh-install

fresh-install-destroy:
	export ENOS_VAR_local_boundary_dir="${GOPATH}/bin" &&\
	export ENOS_VAR_enos_user=${USER} &&\
	enos scenario destroy --chdir=./fresh-install
