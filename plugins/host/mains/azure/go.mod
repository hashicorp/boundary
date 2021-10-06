module github.com/hashicorp/boundary/plugins/host/mains/azure

go 1.16

replace github.com/hashicorp/boundary/plugins => ../../..

require (
	github.com/hashicorp/boundary-plugin-host-azure v0.0.0-20210930162319-6b85f1d5964d
	github.com/hashicorp/boundary/sdk v0.0.12-0.20211006192840-ea88a3d81370
	github.com/hashicorp/go-hclog v0.16.2
	github.com/hashicorp/go-plugin v1.4.3 // indirect
)
