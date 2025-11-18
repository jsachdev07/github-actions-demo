1 — Project layout
eks-terraform/
├─ provider.tf
├─ variables.tf
├─ vpc.tf
├─ iam.tf
├─ eks.tf
├─ node_group.tf
├─ outputs.tf

2 — provider.tf
terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}


This sets the AWS provider and Terraform version constraint. Adjust provider version if you have specific requirements.

3 — variables.tf
variable "aws_region" {
  description = "AWS region to create resources in"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "demo-eks-cluster"
}

variable "vpc_cidr" {
  description = "CIDR for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "List of public subnet CIDRs (one per AZ intended)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "List of private subnet CIDRs (one per AZ intended)"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24"]
}

variable "node_group_desired_capacity" {
  description = "Desired capacity for node group"
  type        = number
  default     = 2
}

variable "node_group_min_size" {
  description = "Min size for node group"
  type        = number
  default     = 1
}

variable "node_group_max_size" {
  description = "Max size for node group"
  type        = number
  default     = 3
}

variable "node_instance_type" {
  description = "EC2 instance type for nodes"
  type        = string
  default     = "t3.medium"
}

variable "cluster_version" {
  description = "Kubernetes version for EKS"
  type        = string
  default     = "1.27"
}


Adjust defaults to match your needs and region availability. Kubernetes versions supported vary by region — if you need the latest supported version for your account/region, verify in the AWS console or CLI.

4 — vpc.tf
# Simple VPC with public and private subnets, internet gateway, NAT (using NAT Gateway).
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "${var.cluster_name}-vpc"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags = {
    Name = "${var.cluster_name}-igw"
  }
}

# Public subnets
resource "aws_subnet" "public" {
  for_each = toset(var.public_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  map_public_ip_on_launch = true
  availability_zone = element(data.aws_availability_zones.available.names, index(var.public_subnet_cidrs, each.value))
  tags = {
    Name = "${var.cluster_name}-public-${each.key}"
    "kubernetes.io/role/elb" = "1"
  }
}

# Private subnets (for worker nodes and EKS)
resource "aws_subnet" "private" {
  for_each = toset(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  map_public_ip_on_launch = false
  availability_zone = element(data.aws_availability_zones.available.names, index(var.private_subnet_cidrs, each.value))
  tags = {
    Name = "${var.cluster_name}-private-${each.key}"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Route table for public subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags = {
    Name = "${var.cluster_name}-public-rt"
  }
}

resource "aws_route" "default_public_route" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public_assoc" {
  for_each      = aws_subnet.public
  subnet_id     = each.value.id
  route_table_id = aws_route_table.public.id
}

# NAT Gateway for private subnets (simple single NAT per VPC; for production use per-AZ NATs)
resource "aws_eip" "nat" {
  vpc = true
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id
  subnet_id     = element(values(aws_subnet.public).*id, 0)
  depends_on    = [aws_internet_gateway.this]
  tags = {
    Name = "${var.cluster_name}-nat"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags = {
    Name = "${var.cluster_name}-private-rt"
  }
}

resource "aws_route" "private_default" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this.id
}

resource "aws_route_table_association" "private_assoc" {
  for_each = aws_subnet.private
  subnet_id = each.value.id
  route_table_id = aws_route_table.private.id
}


This creates a small VPC with public/private subnets and a NAT gateway. For production use you may want one NAT per AZ and more subnets.

5 — iam.tf
# IAM role and policy for EKS cluster
resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-eks-cluster-role"

  assume_role_policy = data.aws_iam_policy_document.eks_assume_role.json
}

data "aws_iam_policy_document" "eks_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy_attachment" "eks_service_AmazonEKSClusterPolicy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_service_AmazonEKSServicePolicy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
}

# IAM role for node group (EC2)
resource "aws_iam_role" "node_role" {
  name = "${var.cluster_name}-node-role"

  assume_role_policy = data.aws_iam_policy_document.node_assume_role.json
}

data "aws_iam_policy_document" "node_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy_attachment" "node_AmazonEKSWorkerNodePolicy" {
  role       = aws_iam_role.node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_AmazonEC2ContainerRegistryReadOnly" {
  role       = aws_iam_role.node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "node_AmazonEKS_CNI_Policy" {
  role       = aws_iam_role.node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}


The role attachments use AWS-managed policies suitable for EKS-managed node groups. For least privilege, craft narrower policies.

6 — eks.tf
resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  version  = var.cluster_version
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids = concat(values(aws_subnet.public).*id, values(aws_subnet.private).*id)
    endpoint_private_access = false
    endpoint_public_access  = true
    # optionally configure public access CIDR blocks for tighter control
  }

  # Basic logging enable (optional)
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  tags = {
    Name = var.cluster_name
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_service_AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.eks_service_AmazonEKSServicePolicy
  ]
}

# Security group for the EKS cluster control-plane to communicate with worker nodes
resource "aws_security_group" "cluster_sg" {
  name        = "${var.cluster_name}-cluster-sg"
  description = "Cluster security group"
  vpc_id      = aws_vpc.this.id
  tags = { Name = "${var.cluster_name}-cluster-sg" }
}

# Allow all traffic from cluster SG to node SG will be handled by node group security groups (managed by AWS)


aws_eks_cluster creates the control plane. For real-world clusters, consider limiting public access and enabling private endpoint + VPN or Direct Connect.

7 — node_group.tf
resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-ng"
  node_role_arn   = aws_iam_role.node_role.arn
  subnet_ids      = values(aws_subnet.private).*id

  scaling_config {
    desired_size = var.node_group_desired_capacity
    min_size     = var.node_group_min_size
    max_size     = var.node_group_max_size
  }

  instance_types = [var.node_instance_type]

  ami_type = "AL2_x86_64" # Amazon Linux 2; choose different if using arm or other image

  remote_access {
    # Optional: enable SSH access to nodes
    # ec2_ssh_key = aws_key_pair.eks_key.key_name
    ec2_ssh_key = null
  }

  tags = {
    Name = "${var.cluster_name}-node"
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.node_AmazonEC2ContainerRegistryReadOnly,
    aws_iam_role_policy_attachment.node_AmazonEKS_CNI_Policy
  ]
}


This uses an EKS managed node group (simpler operational model). If you need more control (self-managed ASGs, custom AMIs, GPU nodes), use aws_eks_fargate_profile or self-managed EC2 Auto Scaling groups.

8 — outputs.tf
output "cluster_name" {
  description = "EKS cluster name"
  value       = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  description = "EKS API endpoint"
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_cert_authority_data" {
  description = "Base64 certificate authority data for kubeconfig"
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

output "cluster_oidc_issuer" {
  description = "Cluster OIDC issuer URL (if available)"
  value       = try(aws_eks_cluster.this.identity[0].oidc[0].issuer, "")
}

output "node_group_name" {
  description = "Managed node group name"
  value       = aws_eks_node_group.workers.node_group_name
}

output "private_subnet_ids" {
  description = "Private subnet IDs used by EKS nodes"
  value       = values(aws_subnet.private).*id
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = values(aws_subnet.public).*id
}

# Optional kubeconfig template sample (not automatically writing kubeconfig; use aws eks update-kubeconfig)
output "kubeconfig_sample" {
  description = "Sample kubeconfig you can use by replacing <aws_profile_or_creds> and saving to ~/.kube/config"
  value = <<EOF
apiVersion: v1
clusters:
- cluster:
    server: ${aws_eks_cluster.this.endpoint}
    certificate-authority-data: ${aws_eks_cluster.this.certificate_authority[0].data}
  name: ${aws_eks_cluster.this.name}
contexts:
- context:
    cluster: ${aws_eks_cluster.this.name}
    user: aws
  name: ${aws_eks_cluster.this.name}
current-context: ${aws_eks_cluster.this.name}
kind: Config
preferences: {}
users:
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: aws
      args:
        - eks
        - get-token
        - --cluster-name
        - ${aws_eks_cluster.this.name}
      # env: [{name: "AWS_PROFILE", value: "<aws_profile>"}] # optional
EOF
}


The kubeconfig_sample is provided for convenience — the recommended method after apply is to run:

aws eks --region <region> update-kubeconfig --name <cluster-name>


which uses your configured AWS credentials to create a kubeconfig that uses the AWS IAM authenticator.

9 — How to apply (step-by-step commands)
# initialize terraform
terraform init

# preview
terraform plan -out plan.tfplan

# apply
terraform apply "plan.tfplan"
# -or- directly
terraform apply


After apply completes and the cluster is ACTIVE, configure your kubectl:

aws eks --region <aws_region> update-kubeconfig --name <cluster_name>
kubectl get nodes

10 — Notes, tips & next steps

This example uses public endpoint for the control plane. For production, prefer private endpoint with restricted access (and maybe a bastion or AWS PrivateLink).

Node group uses managed node groups (simpler). For more control, use self-managed auto scaling groups or Fargate.

Consider adding:

aws_eks_addon resources (e.g., vpc-cni, kube-proxy) if you want AWS-managed addons.

aws_eks_fargate_profile for serverless compute.

Fine-grained IAM (IRSA) via an OIDC provider (aws_iam_openid_connect_provider) so pods can assume roles.

Autoscaler setup (Karpenter or Cluster Autoscaler).

Observability (CloudWatch Container Insights, Prometheus).

Clean up with terraform destroy when you’re done to avoid charges.

11 — Quick troubleshooting

If aws_eks_cluster gets stuck in CREATING, check IAM role trust policies and required policies are attached to the cluster role.

If nodes are NotReady, check that the node group can reach the control plane (subnets/NAT/route tables, security groups), and that the aws-auth ConfigMap has the node role mapped (managed node groups handle this automatically).

If terraform apply errors about insufficient permissions, ensure your AWS credentials have permissions for EKS, EC2, IAM, VPC, and CloudFormation (EKS uses CloudFormation behind the scenes for some operations).
