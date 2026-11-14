output "vpc_id" {
  value = aws_vpc.vpc.id
}

output "public_subnet_id" {
  value = aws_subnet.public_subnet.id
}

output "private_subnet_id" {
  value = aws_subnet.private_subnet.id
}

output "private_db_subnet_ids" {
  value = [aws_subnet.private_db_subnet_1.id,
  aws_subnet.private_db_subnet_2.id]
}


