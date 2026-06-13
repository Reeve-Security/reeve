output "linux_inventory" {
  description = "Linux endpoint inventory for Ansible."
  value       = module.linux_hetzner.inventory
}

output "windows_inventory" {
  description = "Windows endpoint inventory contract for Ansible."
  value       = module.windows_azure.inventory
}

output "macos_inventory" {
  description = "macOS endpoint inventory contract for Ansible."
  value       = module.macos_tart.inventory
}

