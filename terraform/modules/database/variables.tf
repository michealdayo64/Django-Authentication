variable "project_name" {
  description = "The name of the project"
  type        = string
}

variable "private_db_subnet_ids" {
  description = "List of private subnet IDs for the database"
  type        = list(string)
}

variable "database_security_group_id" {
  description = "Security group ID for the database"
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