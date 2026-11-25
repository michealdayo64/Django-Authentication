resource "aws_db_subnet_group" "this" {
  name = "${var.project_name}-db-subnet-group"

  subnet_ids = var.private_db_subnet_ids

  tags = {
    Name = "${var.project_name}-db-subnet-group"
  }
}

resource "aws_db_instance" "this" {
  identifier = "${var.project_name}-mysql"

  engine         = "mysql"
  engine_version = "8.4.8"

  instance_class        = var.db_instance_class
  allocated_storage     = 20
  max_allocated_storage = 20

  allow_major_version_upgrade = true

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [var.database_security_group_id]

  publicly_accessible = false

  backup_retention_period = 0

  skip_final_snapshot = true

  deletion_protection = false
}