variable "allowed_admin_ip" {
  description = "The IP address allowed to access the EC2 instances"
  type        = string
}

variable "project_name" {
  type = string
}

variable "vpc_id" {
  description = "The ID of the VPC where the security groups will be created"
  type        = string
}
