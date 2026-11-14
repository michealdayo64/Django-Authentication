

data "aws_ami" "ubuntu" {
  most_recent = true

  owners = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}


# Create EC2 Key Pair
resource "aws_key_pair" "deployer1" {
  key_name   = "${var.project_name}-key"
  public_key = file("${path.root}/${var.ssh_public_key_path}")

  tags = {
    Name = "${var.project_name}-key"
  }
}

# Create EC2 Instance
resource "aws_instance" "frontend" {

  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  subnet_id = var.public_subnet_id

  vpc_security_group_ids = [
    var.frontend_security_group_id
  ]

  key_name = aws_key_pair.deployer1.key_name

  associate_public_ip_address = true

  tags = {
    Name = "${var.project_name}-frontend"
  }
}

# Create EC2 Instance
resource "aws_instance" "backend" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  subnet_id = var.private_subnet_id

  vpc_security_group_ids = [
    var.backend_security_group_id
  ]

  key_name = aws_key_pair.deployer1.key_name

  associate_public_ip_address = true


  tags = {
    Name = "${var.project_name}-backend"
  }
}