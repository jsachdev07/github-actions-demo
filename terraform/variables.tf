variable "node_key" {
  description = "EC2 keypair name for SSH access"
  default     = "ap-linux-kp"
}

variable "region" {
  description = "AWS region"
  default     = "ap-south-1"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  default     = "demo-cluster"
}

variable "node_group_name" {
  description = "Node group name"
  default     = "eks-nodes"
}

variable "node_instance_type" {
  description = "EC2 instance type for nodes"
  default     = "t3.medium"
}

variable "desired_capacity" {
  description = "Number of worker nodes"
  default     = 1
}

variable "max_size" {
  description = "Max nodes in the node group"
  default     = 3
}

variable "min_size" {
  description = "Min nodes in the node group"
  default     = 1
}
