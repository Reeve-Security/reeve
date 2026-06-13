variable "endpoints" {
  description = "Linux endpoints keyed by stable endpoint id."
  type = map(object({
    persona         = string
    location        = optional(string, "fsn1")
    server_type     = optional(string, "cx22")
    image           = optional(string, "ubuntu-24.04")
    ssh_key_ids     = optional(list(string), [])
    recording_scene = optional(list(number), [])
  }))
}

