variable "public_subnet_id" {
  description = "List of public subnet IDs"
  type        = string
}

variable "private_subnet_id" {
  description = "List of private subnet IDs"
  type        = string
}

variable "frontend_security_group_id" {
  description = "Security group ID for the frontend EC2 instance"
  type        = string
}

variable "backend_security_group_id" {
  description = "Security group ID for the backend EC2 instance"
  type        = string
}

variable "project_name" {
  description = "The name of the project"
  type        = string
}

variable "ssh_public_key_path" {
  description = "The public key for the EC2 key pair"
  type        = string
}

variable "instance_type" {
  description = "The instance type for the EC2 instances"
  type        = string
}