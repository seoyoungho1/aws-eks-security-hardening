terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "ap-northeast-2"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

# CKV2_AWS_12: 기본 보안 그룹 트래픽 차단
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  ingress = []
  egress  = []
}

# CKV_AWS_158, CKV_AWS_338: CloudWatch 로그 그룹 KMS 암호화 적용 및 보존 기간 365일(1년) 이상 설정
resource "aws_cloudwatch_log_group" "flow_log_group" {
  name              = "/aws/vpc/flow-log"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.eks_secrets.arn
}

data "aws_iam_policy_document" "flow_log_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_log_role" {
  name               = "vpc-flow-log-role"
  assume_role_policy = data.aws_iam_policy_document.flow_log_assume.json
}

data "aws_iam_policy_document" "flow_log_policy" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow_log_group.arn}:*"]
    effect    = "Allow"
  }
}

resource "aws_iam_role_policy" "flow_log_inline" {
  name   = "vpc-flow-log-inline-policy"
  role   = aws_iam_role.flow_log_role.id
  policy = data.aws_iam_policy_document.flow_log_policy.json
}

resource "aws_flow_log" "main_flow_log" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.flow_log_group.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_subnet" "pub_1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false
}

resource "aws_subnet" "pub_2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "ap-northeast-2b"
  map_public_ip_on_launch = false
}

resource "aws_route_table_association" "rta_1" {
  subnet_id      = aws_subnet.pub_1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "rta_2" {
  subnet_id      = aws_subnet.pub_2.id
  route_table_id = aws_route_table.public.id
}

# CKV_AWS_23, CKV_AWS_382, CKV2_AWS_5: Description 추가, 안전한 egress 지정, 노드그룹에 어태치
resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Secure security group limiting access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTPS within VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Allow secure egress to HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "cluster_role" {
  name = "secure-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster_role.name
}

# CKV_AWS_109, CKV_AWS_111, CKV_AWS_356, CKV2_AWS_64: KMS 정책 최소 권한 원칙 적용 (와일드카드 범위 축소)
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "kms_policy" {
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:TagResource",
      "kms:UntagResource"
    ]
    resources = [aws_kms_key.eks_secrets.arn]
  }
}

resource "aws_kms_key" "eks_secrets" {
  description             = "EKS Secret Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_key_policy" "eks_secrets_policy" {
  key_id = aws_kms_key.eks_secrets.id
  policy = data.aws_iam_policy_document.kms_policy.json
}

# CKV_AWS_39: EKS 퍼블릭 엔드포인트 비활성화 (Private 전용 또는 엄격한 CIDR 제한)
resource "aws_eks_cluster" "remediated_cluster" {
  name     = "remediated-eks-cluster"
  role_arn = aws_iam_role.cluster_role.arn

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
    resources = ["secrets"]
  }

  vpc_config {
    subnet_ids             = [aws_subnet.pub_1.id, aws_subnet.pub_2.id]
    endpoint_public_access = false
  }

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_kms_key_policy.eks_secrets_policy
  ]
}

resource "aws_iam_role" "node_role" {
  name = "secure-eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "node_amazon_eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_role.name
}

resource "aws_iam_role_policy_attachment" "node_amazon_eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_role.name
}

resource "aws_iam_role_policy_attachment" "node_amazon_ec2_container_registry_read_only" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node_role.name
}

resource "aws_eks_node_group" "worker_nodes" {
  cluster_name    = aws_eks_cluster.remediated_cluster.name
  node_group_name = "remediated-node-group"
  node_role_arn   = aws_iam_role.node_role.name
  subnet_ids      = [aws_subnet.pub_1.id, aws_subnet.pub_2.id]

  # CKV2_AWS_5 해결을 위해 위에서 만든 secure_sg 보안 그룹을 명시적으로 연결
  remote_access {
    ec2_ssh_key               = null
    source_security_group_ids = [aws_security_group.secure_sg.id]
  }

  scaling_config {
    desired_size = 1
    max_size     = 2
    min_size     = 1
  }

  instance_types = ["t3.small"]

  depends_on = [
    aws_route_table_association.rta_1,
    aws_route_table_association.rta_2,
    aws_iam_role_policy_attachment.node_amazon_eks_worker_node_policy,
    aws_iam_role_policy_attachment.node_amazon_eks_cni_policy,
    aws_iam_role_policy_attachment.node_amazon_ec2_container_registry_read_only,
  ]

  timeouts {
    create = "50m"
    update = "50m"
    delete = "50m"
  }
}
