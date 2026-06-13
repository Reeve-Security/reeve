variable "server_name" {
  description = "Disposable VPS name."
  type        = string
  default     = "reeve-phase1-validation"
}

variable "image" {
  description = "Hetzner image slug."
  type        = string
  default     = "ubuntu-24.04"
}

variable "server_type" {
  description = "Hetzner server type. CX (Intel) is EU-only; use CPX (AMD) or CAX (ARM) for non-EU locations like ash, hil, sin. cpx11 = cheapest x86 (2 vCPU, 2 GB, ~€4.35/mo)."
  type        = string
  default     = "cpx11"
}

variable "location" {
  description = "Hetzner location. Examples: ash, fsn1, nbg1, hel1."
  type        = string
  default     = "ash"
}

variable "ssh_key_name" {
  description = "Name of the SSH key already registered in Hetzner Cloud."
  type        = string
  default     = "reeve-test-founder"
}
