provider "aws" {
  version = "~> 3.0"
  region  = "us-east-1"
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  private_subnet = [
    aws_subnet.private_0.id,
    aws_subnet.private_1.id,
    aws_subnet.private_2.id,
  ]

  public_subnet = [
    aws_subnet.public_0.id,
    aws_subnet.public_1.id,
    aws_subnet.public_2.id,
  ]
}

# VPC resources
resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = var.tag
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = var.tag
  }
}

# Subnets
resource "aws_subnet" "public_0" {
  vpc_id            = aws_vpc.main.id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "10.0.1.0/24"

  tags = {
    Name = "${var.tag}-public-0"
  }
}

resource "aws_subnet" "public_1" {
  vpc_id            = aws_vpc.main.id
  availability_zone = data.aws_availability_zones.available.names[1]
  cidr_block        = "10.0.2.0/24"

  tags = {
    Name = "${var.tag}-public-1"
  }
}

resource "aws_subnet" "public_2" {
  vpc_id            = aws_vpc.main.id
  availability_zone = data.aws_availability_zones.available.names[2]
  cidr_block        = "10.0.3.0/24"

  tags = {
    Name = "${var.tag}-public-2"
  }
}

resource "aws_subnet" "private_0" {
  vpc_id            = aws_vpc.main.id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "10.0.4.0/24"

  tags = {
    Name = "${var.tag}-private-0"
  }
}

resource "aws_subnet" "private_1" {
  vpc_id            = aws_vpc.main.id
  availability_zone = data.aws_availability_zones.available.names[1]
  cidr_block        = "10.0.5.0/24"

  tags = {
    Name = "${var.tag}-private-1"
  }
}

resource "aws_subnet" "private_2" {
  vpc_id            = aws_vpc.main.id
  availability_zone = data.aws_availability_zones.available.names[2]
  cidr_block        = "10.0.6.0/24"

  tags = {
    Name = "${var.tag}-private-2"
  }
}

resource "aws_eip" "nat" {
  vpc = true
  tags = {
    Name = var.tag
  }
}

resource "aws_nat_gateway" "private_0" {
  subnet_id     = aws_subnet.private_0.id
  allocation_id = aws_eip.nat.id

  tags = {
    Name = "${var.tag}-private-0"
  }
}

# Public Routes
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.tag}-public"
  }
}

resource "aws_route_table_association" "public_subnets" {
  count          = 3
  subnet_id      = local.public_subnet[count.index]
  route_table_id = aws_route_table.public.id
}

resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id

  timeouts {
    create = "5m"
  }
}

# Private Routes
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.tag}-private"
  }
}

resource "aws_route_table_association" "private_subnets" {
  count          = 3
  subnet_id      = local.private_subnet[count.index]
  route_table_id = aws_route_table.private.id
}

resource "aws_route" "nat_gateway" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.private_0.id

  timeouts {
    create = "5m"
  }
}

# EC2 Instances
resource "aws_key_pair" "boundary" {
  key_name   = "boundary-demo"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxBc8jthfF76b2OdoE3kbNb17y+BKlhMhKN9HpYsHV1zD4F/wqJqufhF05ZsoOj5rXyKkxoTNBgMawxR/FWDzmhJLFVLaCzjRiggCdEFpOGbnggT/Mt3HruRLBmIOgk5Zj3+SMrtYqflOTMUahu1+4YZO2auqBIEJ/Vqm6Ja8y38I/ceOuQ9T+dbUJJ6FCtvtVq7oQcE6JVi78edgJDflCREYUyNJQXgnBQP4KZLjvSEt3yyKLCEoKGMmPYMAm+7jCEnjLft9N2l9t1SPAU9j80Qaf/72XtqaibEb97jFFXBW01RKA1BvN4uwCrw3I3unmB4YJU/m40Y66nwAm0b5j jeffmalnick@Jeffs-MBP"

  tags = {
    Name = "${var.tag}"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "worker" {
  count                  = 3
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  subnet_id              = local.private_subnet[count.index]
  key_name               = aws_key_pair.boundary.key_name
  vpc_security_group_ids = [aws_security_group.worker.id]

  tags = {
    Name = "${var.tag}-worker-${count.index}"
  }
}

resource "aws_eip" "worker" {
  count    = 3
  instance = aws_instance.worker[count.index].id
  vpc      = true

  tags = {
    Name = "${var.tag}-worker-${count.index}"
  }
}

resource "aws_instance" "controller" {
  count                  = 3
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  subnet_id              = local.public_subnet[count.index]
  key_name               = aws_key_pair.boundary.key_name
  vpc_security_group_ids = [aws_security_group.controller.id]

  tags = {
    Name = "${var.tag}-controller-${count.index}"
  }
}

resource "aws_eip" "controller" {
  count = 3
  vpc   = true

  tags = {
    Name = "${var.tag}-controller-${count.index}"
  }
}

resource "aws_eip_association" "eip_assoc" {
  count         = 3
  instance_id   = aws_instance.controller[count.index].id
  allocation_id = aws_eip.controller[count.index].id
}

resource "null_resource" "controller_config" {
  count = 3

  triggers = {
    cluster_instance_ids = "${join(",", aws_instance.controller.*.id)}"
  }

  connection {
    type        = "ssh"
    user        = "ubuntu"
    private_key = file("~/.ssh/id_rsa")
    host        = aws_instance.controller[count.index].public_ip
  }

  provisioner "file" {
    source      = "${var.boundary_bin}/boundary"
    destination = "~/boundary"
  }

  provisioner "file" {
    source      = "config/controller.hcl"
    destination = "~/controller.hcl"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo snap install docker",
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "sudo su && docker run --name some-postgres -p 5432:5432 -e POSTGRES_PASSWORD=easy -d postgres"
    ]
  }
}

resource "aws_security_group" "controller" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.tag}-controller"
  }
}

resource "aws_security_group_rule" "allow_ssh_controller" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.controller.id
}

resource "aws_security_group_rule" "allow_egress_controller" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.controller.id
}

resource "aws_security_group" "worker" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.tag}-worker"
  }
}

resource "aws_security_group_rule" "allow_ssh_worker" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.main.cidr_block]
  security_group_id = aws_security_group.worker.id
}

resource "aws_security_group_rule" "allow_egress_worker" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.worker.id
}

# Controller LB
resource "aws_lb" "controller" {
  name               = "${var.tag}-controller"
  load_balancer_type = "network"
  internal           = false
  subnets            = local.public_subnet
  #  security_groups    = [aws_security_group.controller_lb.id]

  tags = {
    Name = "${var.tag}-controller"
  }
}

resource "aws_lb_target_group" "controller" {
  name     = "${var.tag}-controller"
  port     = 9200
  protocol = "TCP"
  vpc_id   = aws_vpc.main.id

  stickiness {
    enabled = false
    type    = "lb_cookie"
  }
}

resource "aws_lb_target_group_attachment" "controller" {
  count            = 3
  target_group_arn = aws_lb_target_group.controller.arn
  target_id        = aws_instance.controller[count.index].id
  port             = 9200
}

resource "aws_lb_listener" "controller" {
  load_balancer_arn = aws_lb.controller.arn
  port              = "9200"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.controller.arn
  }
}

resource "aws_security_group" "controller_lb" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.tag}-controller-lb"
  }
}

resource "aws_security_group_rule" "allow_9200" {
  type              = "ingress"
  from_port         = 9200
  to_port           = 9200
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.controller_lb.id
}
