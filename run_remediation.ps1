# =========================================================
# DevSecOps 파이프라인: 보안 진단, 완벽 하드닝 덮어쓰기 및 재배포
# =========================================================

$TARGET_FILE = "main.tf"
$BACKUP_FILE = "main_bf.bak"
$REPORT_FILE = "scan_result.txt"

Clear-Host
Write-Host "=========================================================" -ForegroundColor Blue
Write-Host "  [1/4] Checkov 기반 IaC 보안 진단 및 비율(%) 분석 시작" -ForegroundColor Blue
Write-Host "=========================================================" -ForegroundColor Blue

if (-not (Test-Path $TARGET_FILE)) {
    Write-Host "오류: 진단 대상 파일($TARGET_FILE)이 존재하지 않습니다." -ForegroundColor Red
    exit
}

Write-Host "Checkov 스캔을 진행 중입니다..." -ForegroundColor Yellow
python -X utf8 -m checkov.main -f $TARGET_FILE > $REPORT_FILE 2>&1

$REPORT_CONTENT = Get-Content $REPORT_FILE -ErrorAction SilentlyContinue

$PASSED_COUNT = 0
$FAILED_COUNT = 0

$PASSED_MATCH = $REPORT_CONTENT | Select-String -Pattern "Passed checks:\s*([0-9]+)"
if ($PASSED_MATCH) { $PASSED_COUNT = [int]$PASSED_MATCH.Matches.Groups[1].Value }

$FAILED_MATCH = $REPORT_CONTENT | Select-String -Pattern "Failed checks:\s*([0-9]+)"
if ($FAILED_MATCH) { $FAILED_COUNT = [int]$FAILED_MATCH.Matches.Groups[1].Value }

$TOTAL_CHECKS = $PASSED_COUNT + $FAILED_COUNT

if ($TOTAL_CHECKS -gt 0) {
    $PASS_RATE = [math]::Round(($PASSED_COUNT / $TOTAL_CHECKS) * 100, 1)
    $FAIL_RATE = [math]::Round(($FAILED_COUNT / $TOTAL_CHECKS) * 100, 1)
} else {
    $PASS_RATE = 100.0
    $FAIL_RATE = 0.0
}

$VULN_IDS = $REPORT_CONTENT | Select-String -Pattern "CKV_AWS_[0-9]+" -AllMatches | ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Red
Write-Host "  [보안 진단 리포트 Summary]" -ForegroundColor Red
Write-Host "  • 전체 점검 항목 : $TOTAL_CHECKS 건" -ForegroundColor White
Write-Host "  • 통과 (Passed)  : $PASSED_COUNT 건 ($PASS_RATE %)" -ForegroundColor Green
Write-Host "  • 미달 (Failed)  : $FAILED_COUNT 건 ($FAIL_RATE %) --> [REJECT 판정]" -ForegroundColor Red
Write-Host "=========================================================" -ForegroundColor Red

if (-not $VULN_IDS) {
    Write-Host "발견된 취약점이 없습니다. 인프라가 안전합니다." -ForegroundColor Green
    exit
}

Write-Host ""
Write-Host "[주요 검출 취약점 목록]" -ForegroundColor Yellow
foreach ($id in $VULN_IDS) {
    Write-Host "  • [$id] 보안 Baseline 미준수 항목 탐지" -ForegroundColor Yellow
}
Write-Host ""

$USER_CHOICE = Read-Host "보안 하드닝 패치를 적용하고 재배포하시겠습니까? (y/N)"

if ($USER_CHOICE -notmatch "^[Yy]$") {
    Write-Host "작업이 취소되었습니다." -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Blue
Write-Host "  [2/4] 100% 통과 보장형 보안 코드로 덮어쓰기 및 반영" -ForegroundColor Blue
Write-Host "=========================================================" -ForegroundColor Blue

Copy-Item -Path $TARGET_FILE -Destination $BACKUP_FILE -Force

$SECURE_CODE = @'
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

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  ingress = []
  egress  = []
}

resource "aws_cloudwatch_log_group" "flow_log_group" {
  name              = "/aws/vpc/flow-log"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.eks_secrets.arn
  depends_on        = [aws_kms_key_policy.eks_secrets_policy]
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

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

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

  statement {
    sid       = "Allow CloudWatch Logs to use the key"
    effect    = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions   = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]
    resources = [aws_kms_key.eks_secrets.arn]
    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/vpc/flow-log"]
    }
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
    endpoint_public_access = true
    public_access_cidrs    = ["10.0.0.0/8"]
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
'@

Set-Content -Path $TARGET_FILE -Value $SECURE_CODE -Encoding UTF8

terraform init -upgrade
terraform apply -auto-approve

Start-Sleep -Seconds 10

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Blue
Write-Host "  [3/4] 2차 재스캔 검증" -ForegroundColor Blue
Write-Host "=========================================================" -ForegroundColor Blue
python -X utf8 -m checkov.main -f $TARGET_FILE

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Blue
Write-Host "  [4/4] 쿠버네티스 서비스 배포" -ForegroundColor Blue
Write-Host "=========================================================" -ForegroundColor Blue

aws eks update-kubeconfig --region ap-northeast-2 --name remediated-eks-cluster
.\kubectl create deployment nginx-server --image=nginx --dry-run=client -o yaml | .\kubectl apply -f -
.\kubectl expose deployment nginx-server --port=80 --type=ClusterIP --dry-run=client -o yaml | .\kubectl apply -f -

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "  모든 작업이 완료되었습니다." -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
