module "linux_hetzner" {
  source    = "./modules/linux-hetzner"
  endpoints = var.linux_endpoints
}

module "windows_azure" {
  source    = "./modules/windows-azure"
  endpoints = var.windows_endpoints
}

module "macos_tart" {
  source    = "./modules/macos-tart"
  endpoints = var.macos_endpoints
}

