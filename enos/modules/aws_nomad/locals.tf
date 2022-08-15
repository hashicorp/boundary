locals {
  name_suffix       = "${var.project_name}-${var.environment}"
  consul_bin_path   = "${var.consul_install_dir}/consul"
  nomad_cluster_tag = coalesce(var.nomad_cluster_tag, "nomad-server-${random_string.cluster_id.result}")
  nomad_instances   = toset([for idx in range(var.instance_count) : tostring(idx)])

  cidr_blocks = ["${data.enos_environment.localhost.public_ip_address}/32", join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block)]
  open_ports = [
    {
      description = "SSH"
      from        = 22
      to          = 22
      protocol    = "tcp"
    },
    {
      description = "Nomad HTTP API, internal RPC, Serf WAN TCP"
      from        = 4646
      to          = 4648
      protocol    = "tcp"
    },
    {
      description = "Serf WAN UDP"
      from        = 4648
      to          = 4648
      protocol    = "udp"
    },
    {
      description = "Consul Agent TCP"
      from        = 8301
      to          = 8301
      protocol    = "tcp"
    },
    {
      description = "Consul Agent UDP"
      from        = 8301
      to          = 8301
      protocol    = "udp"
    },
    {
      description = "Boundary TCP"
      from        = 9200
      to          = 9200
      protocol    = "tcp"
    },
  ]
}
