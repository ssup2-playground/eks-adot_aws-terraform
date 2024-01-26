## Provider
provider "aws" {
  region = local.region
}

provider "aws" {
  alias  = "ecr"
  region = "us-east-1"
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }

  experiments {
    manifest = false
  }
}

provider "kubectl" {
  apply_retry_count      = 5
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "opensearch" {
  url         = aws_opensearch_domain.opensearch.endpoint
  aws_region  = local.region
  healthcheck = false
}

## Data
data "aws_availability_zones" "available" {}

data "aws_caller_identity" "current" {}

data "aws_ecrpublic_authorization_token" "token" {
  provider = aws.ecr
}

## S3
resource "aws_s3_bucket" "log" {
  bucket = local.s3_bucket_log
}

resource "aws_s3_object" "loki" {
  bucket = aws_s3_bucket.log.id
  acl    = "private"
  key    = format("%s/", local.s3_dir_loki)
  source = "/dev/null"
}

resource "aws_vpc_endpoint" "s3_endpoint" {
  vpc_id       = module.vpc.vpc_id
  service_name = "com.amazonaws.${local.region}.s3"

  tags = {
    Name = format("%s-ob-s3-endpoint", local.name)
  }
}

resource "aws_vpc_endpoint_route_table_association" "s3_endpoint_routetable" {
  count           = length(local.azs)
  vpc_endpoint_id = aws_vpc_endpoint.s3_endpoint.id
  route_table_id  = module.vpc.private_route_table_ids[count.index]
}

## VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-ob-vpc", local.name)

  cidr             = local.vpc_cidr
  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k + 4)]

  enable_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  manage_default_network_acl    = true
  manage_default_route_table    = true
  manage_default_security_group = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1 # for AWS Load Balancer Controller
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1                               # for AWS Load Balancer Controller
    "karpenter.sh/discovery"          = format("%s-ob-eks", local.name) # for Karpenter
  }
}

## AMP
module "prometheus" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  workspace_alias = format("%s-amp", local.name)
}

## EKS
module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-ob-eks", local.name)
  cluster_version = "1.28"

  vpc_id                          = module.vpc.vpc_id
  subnet_ids                      = module.vpc.private_subnets
  cluster_endpoint_public_access  = true

  manage_aws_auth_configmap = true

  ## Addons
  cluster_addons = {
    coredns = {
      addon_version = "v1.10.1-eksbuild.5"
      configuration_values = jsonencode({
        nodeSelector: {
          type: "core"
        }
        tolerations: [
          {
            key: "type",
            value: "core",
            operator: "Equal",
            effect: "NoSchedule"
          }
        ]
      })
    }
    vpc-cni = {
      addon_version = "v1.14.1-eksbuild.1"
    }
    kube-proxy = {
      addon_version = "v1.28.1-eksbuild.1"
    }
    aws-ebs-csi-driver = {
      addon_version = "v1.25.0-eksbuild.1"
      configuration_values = jsonencode({
        controller: {
          nodeSelector: {
            type: "core"
          }
          tolerations: [
            {
              key: "type",
              value: "core",
              operator: "Equal",
              effect: "NoSchedule"
            }
          ]
        }
      })
    }
    adot = {
      addon_version = "v0.90.0-eksbuild.1"
      configuration_values = jsonencode({
        nodeSelector: {
          type: "core"
        }
        tolerations: [
          {
            key: "type",
            value: "core",
            operator: "Equal",
            effect: "NoSchedule"
          }
        ]
      })
    }
  }

  ## Fargate
  fargate_profiles = {
    karpenter = {
      selectors = [
        { namespace = "karpenter" }
      ]
    }
  }

  ## Node Security Group
  node_security_group_tags = {
    "karpenter.sh/discovery" = format("%s-ob-eks", local.name) # for Karpenter
  }
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
  }

  aws_auth_roles = [
    {
      ## for Karpenter
      rolearn  = module.karpenter.role_arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
        "system:bootstrappers",
        "system:nodes",
      ]
    }
  ]
}

## EKS / Karpenter
module "karpenter" {
  source = "terraform-aws-modules/eks/aws//modules/karpenter"

  cluster_name           = module.eks.cluster_name
  irsa_oidc_provider_arn = module.eks.oidc_provider_arn

	enable_karpenter_instance_profile_creation = true

  iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }
}

resource "helm_release" "karpenter" {
  namespace        = "karpenter"
  create_namespace = true

  name       = "karpenter"
  chart      = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  version    = "v0.32.5"

  set {
    name  = "settings.aws.clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "settings.aws.clusterEndpoint"
    value = module.eks.cluster_endpoint
  }
  set {
    name  = "settings.aws.interruptionQueueName"
    value = module.karpenter.queue_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.karpenter.irsa_arn
  }

  depends_on = [
    module.karpenter
  ]
}

resource "kubectl_manifest" "karpenter_nodepool_core" {
  yaml_body = <<-YAML
    apiVersion: karpenter.sh/v1beta1
    kind: NodePool
    metadata:
      name: core
    spec:
      template:
        metadata:
          labels:
            type: core
        spec:
          nodeClassRef:
            name: default
          requirements:
            - key: karpenter.sh/capacity-type
              operator: In
              values: ["on-demand"]
            - key: karpenter.k8s.aws/instance-family
              operator: In
              values: ["m5"]
            - key: karpenter.k8s.aws/instance-size
              operator: In
              values: ["xlarge"]
          taints:
          - key: type
            value: core
            effect: NoSchedule
      consolidationPolicy: WhenEmpty
      consolidateAfter: 30s
  YAML

  depends_on = [
    helm_release.karpenter
  ]
}

resource "kubectl_manifest" "karpenter_nodepool_default" {
  yaml_body = <<-YAML
    apiVersion: karpenter.sh/v1beta1
    kind: NodePool
    metadata:
      name: default
    spec:
      template:
        metadata:
          labels:
            type: service
        spec:
          nodeClassRef:
            name: default
          requirements:
            - key: karpenter.sh/capacity-type
              operator: In
              values: ["on-demand"]
            - key: karpenter.k8s.aws/instance-family
              operator: In
              values: ["m5"]
            - key: karpenter.k8s.aws/instance-size
              operator: In
              values: ["xlarge"]
      consolidationPolicy: WhenEmpty
      consolidateAfter: 30s
  YAML

  depends_on = [
    helm_release.karpenter
  ]
}

resource "kubectl_manifest" "karpenter_ec2nodeclass_default" {
  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1beta1
    kind: EC2NodeClass
    metadata:
      name: default
    spec:
      amiFamily: AL2
      role: ${module.karpenter.role_name}
      subnetSelectorTerms:
        - tags:
            karpenter.sh/discovery: ${module.eks.cluster_name}
      securityGroupSelectorTerms:
        - tags:
            karpenter.sh/discovery: ${module.eks.cluster_name}
      tags:
        karpenter.sh/discovery: ${module.eks.cluster_name}
  YAML

  depends_on = [
    helm_release.karpenter
  ]
}

## EKS / Cert Manager
resource "helm_release" "cert_manager" {
  create_namespace = true
  namespace  = "cert-manager"

  name       = "cert-manager"
  chart      = "cert-manager"
  repository = "https://charts.jetstack.io"
  version    = "v1.13.3"
 
  values = [
    file("${path.module}/helm-values/cert-manager.yaml")
  ]
  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }

  depends_on = [
    helm_release.karpenter
  ]
}

## EKS / Load Balancer Controller
module "eks_load_balancer_controller_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("eks-aws-load-balancer-controller-%s-ob", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "aws_load_balancer_controller" {
  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"
 
  values = [
    file("${path.module}/helm-values/aws-load-balancer-controller.yaml")
  ]

  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.eks_load_balancer_controller_irsa_role.iam_role_arn
  }

  depends_on = [
    module.eks_load_balancer_controller_irsa_role,
    helm_release.karpenter
  ]
}

## EKS / Loki
#resource "helm_release" "loki" {
#  namespace        = "monitoring"
#  create_namespace = true

#  name       = "loki"
#  chart      = "loki"
#  repository = "https://grafana.github.io/helm-charts"
#  version    = "v5.38.0"
 
#  values = [
#    file("${path.module}/helm-values/loki.yaml")
#  ]
#}

## EKS / Tempo
resource "helm_release" "tempo" {
  namespace        = "monitoring"
  create_namespace = true

  name       = "tempo"
  chart      = "tempo"
  repository = "https://grafana.github.io/helm-charts"
  version    = "v1.7.1"
 
  values = [
    file("${path.module}/helm-values/tempo.yaml")
  ]
}

## EKS / Grafana 
resource "helm_release" "grafana" {
  namespace        = "monitoring"
  create_namespace = true

  name       = "grafana"
  chart      = "grafana"
  repository = "https://grafana.github.io/helm-charts"
  version    = "v7.0.8"
 
  values = [
    file("${path.module}/helm-values/grafana.yaml")
  ]

  depends_on = [
    helm_release.karpenter
  ]
}

## CloudWatch Log Group
resource "aws_cloudwatch_log_group" "onebyone" {
  name = format("%s-onebyone", local.name)
}

resource "aws_cloudwatch_log_group" "atonce" {
  name = format("%s-atonce", local.name)
}

## OpenSearch
resource "aws_opensearch_domain" "opensearch" {
  domain_name    = format("%s-opensearch", local.name)
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type = "m5.xlarge.search"
  }

  advanced_security_options {
	  enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "admin"
      master_user_password = "Admin123!"
    }
  }

  encrypt_at_rest {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  node_to_node_encryption {
    enabled = true
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
  }
}

data "aws_iam_policy_document" "opensearch_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["es:*"]
    resources = ["${aws_opensearch_domain.opensearch.arn}/*"]

    condition {
		  test     = "IpAddress"
      variable = "aws:SourceIp"
      values   = ["127.0.0.1/32"]
    }
  }
}

resource "aws_opensearch_domain_policy" "opensearch_access_policy" {
  domain_name     = aws_opensearch_domain.opensearch.domain_name
  access_policies = data.aws_iam_policy_document.opensearch_policy.json
}

## OpenSearch / Injest
resource "aws_iam_role" "opensearch_injest" {
  name = "OpenSearchInjest"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "osis-pipelines.amazonaws.com"
        }	
      },
    ]
  })

  inline_policy {
    name = "OpenSearchInjest"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = ["es:DescribeDomain", "es:ESHttp*"]
          Resource = "*"
        },
      ]
    })
  }
}

resource "awscc_osis_pipeline" "metric_onebyone" {
  pipeline_name = format("%s-metric-oneone", local.name)
  min_units     = 1
  max_units     = 4

  pipeline_configuration_body = <<EOF
version: "2"
otel-metrics-onebyone-pipeline:
  source:
    otel_metrics_source:
      path: "/metrics/onebyone"
  processor:
    - otel_metrics:
  sink:
    - opensearch:
        index: "metrics_onebyone"
        hosts: ["https://${aws_opensearch_domain.opensearch.endpoint}"]
        aws:                  
          sts_role_arn: "${aws_iam_role.opensearch_injest.arn}"
          region: "${local.region}"
EOF

  depends_on = [
	  aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

resource "awscc_osis_pipeline" "metric_atonce" {
  pipeline_name = format("%s-metric-atonce", local.name)
  min_units     = 1
  max_units     = 4

  pipeline_configuration_body = <<EOF
version: "2"
otel-metrics-atonce-pipeline:
  source:
    otel_metrics_source:
      path: "/metrics/atonce"
  processor:
    - otel_metrics:
  sink:
    - opensearch:
        index: "metrics_atonce"
        hosts: ["https://${aws_opensearch_domain.opensearch.endpoint}"]
        aws:                  
          sts_role_arn: "${aws_iam_role.opensearch_injest.arn}"
          region: "${local.region}"
EOF

  depends_on = [
	  aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

resource "awscc_osis_pipeline" "log_onebyone" {
  pipeline_name = format("%s-log-oneone", local.name)
  min_units     = 1
  max_units     = 4

  pipeline_configuration_body = <<EOF
version: "2"
otel-logs-pipeline:
  source:
    otel_logs_source:
      path: "/logs/onebyone"
  processor:
    - parse_json:
        source: "body"                  
    - parse_json:
        source: "kubernetes"                  
    - parse_json:
        source: "annotations"                  
    - parse_json:
        source: "labels"              
    - delete_entries:
        with_keys: ["body", "kubernetes", "annotations", "labels"]
    - date:
        from_time_received: true
        destination: "@timestamp"           
  sink:
    - opensearch:                  
        index: "logs_onebyone"
        hosts: ["https://${aws_opensearch_domain.opensearch.endpoint}"]
        aws:                  
          sts_role_arn: "${aws_iam_role.opensearch_injest.arn}"
          region: "${local.region}"
EOF

  depends_on = [
	  aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

resource "awscc_osis_pipeline" "log_atonce" {
  pipeline_name = format("%s-log-atonce", local.name)
  min_units     = 1
  max_units     = 4

  pipeline_configuration_body = <<EOF
version: "2"
otel-logs-pipeline:
  source:
    otel_logs_source:
      path: "/logs/atonce"
  processor:
    - parse_json:
        source: "body"                  
    - parse_json:
        source: "kubernetes"                  
    - parse_json:
        source: "annotations"                  
    - parse_json:
        source: "labels"              
    - delete_entries:
        with_keys: ["body", "kubernetes", "annotations", "labels"]
    - date:
        from_time_received: true
        destination: "@timestamp"           
  sink:
    - opensearch:                  
        index: "logs_atonce"
        hosts: ["https://${aws_opensearch_domain.opensearch.endpoint}"]
        aws:                  
          sts_role_arn: "${aws_iam_role.opensearch_injest.arn}"
          region: "${local.region}"
EOF

  depends_on = [
	  aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}
