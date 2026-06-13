output "vps_ip" {
  description = "Public IPv4 address for Ansible."
  value       = hcloud_server.reeve_phase1.ipv4_address
}

output "vps_name" {
  description = "Hetzner server name."
  value       = hcloud_server.reeve_phase1.name
}

