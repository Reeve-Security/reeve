variable "linux_endpoints" {
  description = "Linux endpoints keyed by stable endpoint id from variant-matrix.md."
  type = map(object({
    persona         = string
    location        = optional(string, "fsn1")
    server_type     = optional(string, "cx22")
    image           = optional(string, "ubuntu-24.04")
    ssh_key_ids     = optional(list(string), [])
    recording_scene = optional(list(number), [])
  }))
  default = {}
}

variable "windows_endpoints" {
  description = "Windows endpoints keyed by stable endpoint id from variant-matrix.md."
  type = map(object({
    persona         = string
    provider        = string
    size            = optional(string, "Standard_B2ms")
    region          = optional(string, "eastus")
    recording_scene = optional(list(number), [])
  }))
  default = {}
}

variable "macos_endpoints" {
  description = "macOS Tart endpoints keyed by stable endpoint id from variant-matrix.md."
  type = map(object({
    persona         = string
    tart_image      = string
    host            = string
    recording_scene = optional(list(number), [])
  }))
  default = {}
}

variable "artifact_bucket" {
  description = "S3-compatible demo artifact bucket. Empty keeps upload wiring disabled."
  type        = string
  default     = ""
}

