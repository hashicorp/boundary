locals {
  boundary_port = 9200
  open_ports = [
    {
      port = local.boundary_port
      description = "Boundary API"
    },
  ]
}
