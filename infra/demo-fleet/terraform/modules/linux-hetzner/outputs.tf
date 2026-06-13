output "inventory" {
  value = {
    for id, server in hcloud_server.endpoint : id => {
      ansible_host    = server.ipv4_address
      ansible_user    = "root"
      platform        = "linux"
      persona         = var.endpoints[id].persona
      recording_scene = var.endpoints[id].recording_scene
    }
  }
}

