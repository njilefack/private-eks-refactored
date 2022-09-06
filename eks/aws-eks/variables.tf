variable vpc_id {
  type        = string
  default     = "vpc-074f9ddb4065b616a"
  description = "eks cluster vpc"
}

variable "control_plane_subnet_ids" {
  default = ["subnet-05a6400068dd3cf9c", "subnet-02db109f3a386fd04", "subnet-00dcd26e787e062e1"]
}

variable "private_subnet_ids" {
  default = ["subnet-05ee24bfeee851de9", "subnet-06112bfa26ca815cf", "subnet-06545afa248f73968"]
}

variable "bastion-sg" {
  type        = string
  default     = "sg-03619fcf0b2469bf6"
  description = "bastion sg"
}

