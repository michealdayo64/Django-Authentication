variable "project_name" {
  type = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for the private application subnet"
  type        = string
  default     = "10.0.2.0/24"
}


variable "backend_security_group_id" {
  description = "Security group ID for the backend EC2 instance"
  type        = string
}

variable "private_db_subnet_cidr_1" {
  description = "CIDR block for the private database subnet"
  type        = string
  default     = "10.0.3.0/24"
}

variable "private_db_subnet_cidr_2" {
  description = "CIDR block for the private database subnet"
  type        = string
  default     = "10.0.4.0/24"
}


variable "allowed_admin_ip" {
  description = "The IP address allowed to access the EC2 instances"
  type        = string
}

variable "instance_type" {
  type    = string
  default = "t2.micro"
}

variable "ssh_public_key_path" {
  description = "The public key for the EC2 key pair"
  type        = string
}

variable "db_instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "db_name" {
  type = string
}

variable "db_username" {
  type      = string
  sensitive = true
}

variable "db_password" {
  type      = string
  sensitive = true
}