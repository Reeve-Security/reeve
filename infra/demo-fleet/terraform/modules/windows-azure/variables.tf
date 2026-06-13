variable "endpoints" {
  description = "Windows endpoints keyed by stable endpoint id."
  type = map(object({
    persona         = string
    provider        = string
    size            = optional(string, "Standard_B2ms")
    region          = optional(string, "eastus")
    recording_scene = optional(list(number), [])
  }))

  validation {
    condition     = alltrue([for endpoint in values(var.endpoints) : endpoint.provider == "azure"])
    error_message = "windows-azure module only accepts provider = \"azure\"."
  }
}

