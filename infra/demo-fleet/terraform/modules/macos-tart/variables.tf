variable "endpoints" {
  description = "macOS Tart endpoints keyed by stable endpoint id."
  type = map(object({
    persona         = string
    tart_image      = string
    host            = string
    recording_scene = optional(list(number), [])
  }))
}

