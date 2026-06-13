resource "hcloud_server" "endpoint" {
  for_each = var.endpoints

  name        = each.key
  image       = each.value.image
  server_type = each.value.server_type
  location    = each.value.location
  ssh_keys    = each.value.ssh_key_ids

  labels = {
    project = "reeve-demo-fleet"
    persona = each.value.persona
    purpose = "one-shot-recording"
  }
}

