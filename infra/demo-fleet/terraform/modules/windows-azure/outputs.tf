output "inventory" {
  value = {
    for id, endpoint in var.endpoints : id => {
      ansible_host    = null
      ansible_user    = "Administrator"
      platform        = "windows"
      persona         = endpoint.persona
      size            = endpoint.size
      region          = endpoint.region
      recording_scene = endpoint.recording_scene
    }
  }
}

