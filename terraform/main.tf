module "network" {
  source                   = "./modules/network"
  project_name             = var.project_name
  vpc_cidr                 = var.vpc_cidr
  public_subnet_cidr       = var.public_subnet_cidr
  private_subnet_cidr      = var.private_subnet_cidr
  private_db_subnet_cidr_1 = var.private_db_subnet_cidr_1
  private_db_subnet_cidr_2 = var.private_db_subnet_cidr_2
}

module "security" {
  source           = "./modules/security"
  vpc_id           = module.network.vpc_id
  project_name     = var.project_name
  allowed_admin_ip = var.allowed_admin_ip
}

module "compute" {
  source                     = "./modules/compute"
  project_name               = var.project_name
  instance_type              = var.instance_type
  ssh_public_key_path        = var.ssh_public_key_path
  public_subnet_id           = module.network.public_subnet_id
  private_subnet_id          = module.network.private_subnet_id
  frontend_security_group_id = module.security.frontend_security_group_id
  backend_security_group_id  = module.security.backend_security_group_id
}

module "database" {
  source                     = "./modules/database"
  project_name               = var.project_name
  db_instance_class          = var.db_instance_class
  private_db_subnet_ids      = module.network.private_db_subnet_ids
  db_name                    = var.db_name
  db_username                = var.db_username
  db_password                = var.db_password
  database_security_group_id = module.security.database_security_group_id
}