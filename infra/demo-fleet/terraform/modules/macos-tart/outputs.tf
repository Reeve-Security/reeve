output "inventory" {
  value = {
    for id, endpoint in var.endpoints : id => {
      ansible_host    = endpoint.host
      ansible_user    = "admin"
      platform        = "macos"
      persona         = endpoint.persona
      tart_image      = endpoint.tart_image
      recording_scene = endpoint.recording_scene
    }
  }
}

