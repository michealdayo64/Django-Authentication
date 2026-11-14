output "frontend_security_group_id" {
  value = aws_security_group.frontend_sg.id
}

output "backend_security_group_id" {
  value = aws_security_group.backend_sg.id
}

output "database_security_group_id" {
  value = aws_security_group.database_sg.id
}