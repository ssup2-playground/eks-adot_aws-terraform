## Provider
provider "aws" {
  region = local.region
}

provider "aws" {
  alias  = "ecr"
  region = "us-east-1"
}

provider "kubernetes" {
  alias = "observer"

  host                   = module.eks_observer.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_observer.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_observer.cluster_name]
  }
}

provider "kubernetes" {
  alias = "workload"

  host                   = module.eks_workload.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_workload.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_workload.cluster_name]
  }
}

provider "helm" {
  alias = "observer"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_observer.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_observer.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_observer.cluster_name]
    }
  }
}

provider "helm" {
  alias = "workload"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_workload.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_workload.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_workload.cluster_name]
    }
  }
}

provider "kubectl" {
  alias = "observer"

  apply_retry_count      = 5
  host                   = module.eks_observer.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_observer.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_observer.cluster_name]
  }
}

provider "kubectl" {
  alias = "workload"

  apply_retry_count      = 5
  host                   = module.eks_workload.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_workload.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_workload.cluster_name]
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

## IAM
module "iam_policy_os_ingest" {
  source = "terraform-aws-modules/iam/aws//modules/iam-policy"

  name = format("%s_opensearch_ingest", local.name)

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "osis:Ingest",
        ]
        Resource = "*"
      }
    ]
  })
}


## AMP
module "prometheus" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  workspace_alias = format("%s-amp", local.name)
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
  name = format("%s-opensearch-injest", local.name)

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

resource "awscc_osis_pipeline" "metrics" {
  pipeline_name = format("%s-metrics", local.name)
  min_units     = 3
  max_units     = 3

  pipeline_configuration_body = templatefile("${path.module}/osis-configs/metrics.yaml",
    {
      region = local.region,
      opensearch_endpoint = aws_opensearch_domain.opensearch.endpoint,
      sts_role_arn = aws_iam_role.opensearch_injest.arn
    }
  )

  depends_on = [
    aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

resource "awscc_osis_pipeline" "logs" {
  pipeline_name = format("%s-logs", local.name)
  min_units     = 3
  max_units     = 3

  pipeline_configuration_body = templatefile("${path.module}/osis-configs/logs.yaml",
    {
      region = local.region,
      opensearch_endpoint = aws_opensearch_domain.opensearch.endpoint,
      sts_role_arn = aws_iam_role.opensearch_injest.arn
    }
  )

  depends_on = [
    aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

resource "awscc_osis_pipeline" "traces" {
  pipeline_name = format("%s-trace", local.name)
  min_units     = 3
  max_units     = 3

  pipeline_configuration_body = templatefile("${path.module}/osis-configs/traces.yaml",
    {
      region = local.region,
      opensearch_endpoint = aws_opensearch_domain.opensearch.endpoint,
      sts_role_arn = aws_iam_role.opensearch_injest.arn
    }
  )

  depends_on = [
    aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

## VPC
module "vpc_observer" {
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-ob-vpc", local.name)

  cidr             = local.vpc_observer_cidr
  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_observer_cidr, 4, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_observer_cidr, 4, k + 4)]

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
    "kubernetes.io/role/internal-elb" = 1 # for AWS Load Balancer Controller
  }
}

module "vpc_workload" {
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-work-vpc", local.name)

  cidr             = local.vpc_workload_cidr
  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_workload_cidr, 4, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_workload_cidr, 4, k + 4)]

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
    "kubernetes.io/role/internal-elb" = 1 # for AWS Load Balancer Controller
  }
}

module "tgw" {
  source  = "terraform-aws-modules/transit-gateway/aws"

  name = format("%s-tgw", local.name)

  share_tgw = false

  vpc_attachments = {
    vpc_observer = {
      vpc_id      = module.vpc_observer.vpc_id
      subnet_ids  = module.vpc_observer.private_subnets
    }

    vpc_workload = {
      vpc_id     = module.vpc_workload.vpc_id
      subnet_ids = module.vpc_workload.private_subnets
    }
  }
}

resource "aws_route" "vpc_observer_to_vpc_workload" {
  route_table_id         = module.vpc_observer.private_route_table_ids[0]
  destination_cidr_block = local.vpc_workload_cidr
  transit_gateway_id     = module.tgw.ec2_transit_gateway_id
}

resource "aws_route" "vpc_workload_to_vpc_observer" {
  route_table_id         = module.vpc_workload.private_route_table_ids[0]
  destination_cidr_block = local.vpc_observer_cidr
  transit_gateway_id     = module.tgw.ec2_transit_gateway_id
}

## EKS Observer
module "eks_observer" {
  providers = {
    kubernetes = kubernetes.observer
  }

  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-ob-eks", local.name)
  cluster_version = "1.28"

  vpc_id                          = module.vpc_observer.vpc_id
  subnet_ids                      = module.vpc_observer.private_subnets
  cluster_endpoint_public_access  = true

  manage_aws_auth_configmap = true

  ## Managed Nodegroups
  eks_managed_node_groups = {
    worker = {
      min_size     = 3
      max_size     = 3
      desired_size = 3

      instance_types = ["m5.xlarge"]
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }
    }
  }

  ## Addons
  cluster_addons = {
    coredns = {
      addon_version = "v1.10.1-eksbuild.5"
    }
    vpc-cni = {
      addon_version = "v1.14.1-eksbuild.1"
    }
    kube-proxy = {
      addon_version = "v1.28.1-eksbuild.1"
    }
    aws-ebs-csi-driver = {
      addon_version = "v1.25.0-eksbuild.1"
      service_account_role_arn = module.irsa_observer_ebs_csi_plugin.iam_role_arn
    }
    adot = {
      addon_version = "v0.90.0-eksbuild.1"
    }
  }

  ## Node Security Group
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }

  ingress_grafana = {
      description              = "From grafana NLB"
      protocol                 = "-1"
      from_port                = 0
      to_port                  = 0
      type                     = "ingress"
      source_security_group_id = module.sg_grafana.security_group_id
    }
  }
}

module "irsa_observer_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-observer-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS Observer / Cert Manager
resource "helm_release" "observer_cert_manager" {
  provider = helm.observer  

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
    value = module.eks_observer.cluster_name
  }
}

## EKS Observer / Load Balancer Controller
module "irsa_observer_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-observer-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "observer_aws_load_balancer_controller" {
  provider = helm.observer  

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"

  set {
    name  = "clusterName"
    value = module.eks_observer.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_observer_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_observer_load_balancer_controller,
  ]
}

## EKS Observer / Loki
resource "helm_release" "observer_loki" {
  provider = helm.observer  

  namespace        = "observability"
  create_namespace = true

  name       = "loki"
  chart      = "loki"
  repository = "https://grafana.github.io/helm-charts"
  version    = "v6.6.3"
 
  values = [
    file("${path.module}/helm-values/loki.yaml")
  ]
}

## EKS Observer / Tempo
resource "helm_release" "observer_tempo" {
  provider = helm.observer  

  namespace        = "observability"
  create_namespace = true

  name       = "tempo"
  chart      = "tempo"
  repository = "https://grafana.github.io/helm-charts"
  version    = "v1.7.1"
 
  values = [
    file("${path.module}/helm-values/tempo.yaml")
  ]
}

## EKS Observer / Grafana 
module "sg_grafana" {
  source = "terraform-aws-modules/security-group/aws"

  name   = format("%s-grafana-sg", local.name)
  vpc_id = module.vpc_observer.vpc_id

  ingress_with_cidr_blocks = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = "127.0.0.1/32"
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port       = 0
      to_port         = 0
      protocol        = "-1"
      cidr_blocks     = "0.0.0.0/0"
    }
  ]
}

module "irsa_observer_grafana" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-irsa-observer-grafana", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["observability:grafana"]
    }
  }
}

resource "helm_release" "observer_grafana" {
  provider = helm.observer

  namespace        = "observability"
  create_namespace = true

  name       = "grafana"
  chart      = "grafana"
  repository = "https://grafana.github.io/helm-charts"
  version    = "v7.0.8"

  set {
    name  = "serviceAccount.name"
    value = "grafana"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_observer_grafana.iam_role_arn
  }

  values = [
    templatefile("${path.module}/helm-values/grafana.yaml", {
      region     = local.region
      svc_sg     = module.sg_grafana.security_group_id
      amp_eks_ob = format("https://aps-workspaces.%s.amazonaws.com/workspaces/%s", local.region, module.prometheus.workspace_id)
    })
  ]
}

## EKS Observer / App Python
data "kubectl_file_documents" "observer_app_python" {
  content = file("${path.module}/manifests/app-python-ob.yaml")
}

resource "kubectl_manifest" "observer_app_python" {
  provider = kubectl.observer

  for_each = data.kubectl_file_documents.observer_app_python.manifests
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Metric / CloudWatch
module "irsa_observer_adot_metric_cw" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s_irsa_observer_adot_metric_cw", local.name)
  attach_cloudwatch_observability_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["adot-collector:adot-metric-cw"]
    }
  }

  depends_on = [
    module.eks_observer
  ]
}

resource "kubectl_manifest" "observer_adot_metric_cw" {
  for_each = toset(
    split("---",
      templatefile("${path.module}/manifests/adot-metric-cw.yaml",
        {
          cw_role_arn = module.irsa_observer_adot_metric_cw.iam_role_arn
        }
      )
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Metric / AMP
module "irsa_observer_adot_metric_amp" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s_irsa_observer_adot_metric_amp", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["adot-collector:adot-metric-amp"]
    }
  }

  depends_on = [
    module.eks_observer
  ]
}

resource "kubectl_manifest" "observer_adot_metric_amp" {
  for_each = toset(
    split("---",
      templatefile("${path.module}/manifests/adot-metric-amp.yaml",
        {
          aws_region = local.region
          amp_remote_write_endpoint = format("https://aps-workspaces.%s.amazonaws.com/workspaces/%s/api/v1/remote_write", local.region, module.prometheus.workspace_id)
          amp_role_arn = module.irsa_observer_adot_metric_amp.iam_role_arn
        }
      )
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Metric / OpenSearch
module "irsa_observer_adot_metric_os" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name        = format("%s_irsa_observer_adot_metric_os", local.name)
  role_policy_arns = {
    policy = module.iam_policy_os_ingest.arn
  }

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["adot-collector:adot-metric-os"]
    }
  }

  depends_on = [
    module.eks_observer
  ]
}

resource "kubectl_manifest" "observer_adot_metric_os" {
  for_each = toset(
    split("---",
      templatefile("${path.module}/manifests/adot-metric-os.yaml",
        {
          aws_region = local.region
          os_metric_endpoint = awscc_osis_pipeline.metrics.ingest_endpoint_urls[0]
          os_role_arn = module.irsa_observer_adot_metric_os.iam_role_arn
        }
      )
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Log / CloudWatch
module "irsa_observer_adot_log_cw" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s_irsa_observer_adot_log_cw", local.name)
  attach_cloudwatch_observability_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["adot-collector:adot-log-cw"]
    }
  }

  depends_on = [
    module.eks_observer
  ]
}

resource "kubectl_manifest" "observer_adot_log_cw" {
  for_each = toset(
    split("---",
      templatefile("${path.module}/manifests/adot-log-cw.yaml",
        {
          cw_role_arn = module.irsa_observer_adot_log_cw.iam_role_arn
        }
      )
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Log / OpenSearch
module "irsa_observer_adot_log_os" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name        = format("%s_irsa_observer_adot_log_os", local.name)
  role_policy_arns = {
    policy = module.iam_policy_os_ingest.arn
  }

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["adot-collector:adot-log-os"]
    }
  }

  depends_on = [
    module.eks_observer
  ]
}

resource "kubectl_manifest" "observer_adot_log_os" {
  for_each = toset(
    split("---",
      templatefile("${path.module}/manifests/adot-log-os.yaml",
        {
          aws_region = local.region
          os_log_endpoint = awscc_osis_pipeline.logs.ingest_endpoint_urls[0]
          os_role_arn = module.irsa_observer_adot_log_os.iam_role_arn
        }
      )
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Log / Loki
resource "kubectl_manifest" "observer_adot_log_loki" {
  for_each = toset(
    split("---",
      file("${path.module}/manifests/adot-log-loki.yaml")
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Log Destination / Loki
resource "kubectl_manifest" "observer_adot_logd_loki" {
  for_each = toset(
    split("---",
      file("${path.module}/manifests/adot-logd-loki.yaml")
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Trace / X-Ray
module "irsa_observer_adot_trace_xray" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name        = format("%s_irsa_observer_adot_trace_xray", local.name)
  attach_cloudwatch_observability_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["adot-collector:adot-trace-xray"]
    }
  }

  depends_on = [
    module.eks_observer
  ]
}

resource "kubectl_manifest" "observer_adot_trace_xray" {
  for_each = toset(
    split("---",
      templatefile("${path.module}/manifests/adot-trace-xray.yaml",
        {
          aws_region = local.region
          xray_role_arn = module.irsa_observer_adot_trace_xray.iam_role_arn
        }
      )
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Trace / OpenSearch
module "irsa_observer_adot_trace_os" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name        = format("%s_irsa_observer_adot_trace_os", local.name)
  role_policy_arns = {
    policy = module.iam_policy_os_ingest.arn
  }

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["adot-collector:adot-trace-os"]
    }
  }

  depends_on = [
    module.eks_observer
  ]
}

resource "kubectl_manifest" "observer_adot_trace_os" {
  for_each = toset(
    split("---",
      templatefile("${path.module}/manifests/adot-trace-os.yaml",
        {
          aws_region = local.region
          os_trace_endpoint = awscc_osis_pipeline.traces.ingest_endpoint_urls[0]
          os_role_arn = module.irsa_observer_adot_trace_os.iam_role_arn
        }
      )
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Trace / Tempo
resource "kubectl_manifest" "observer_adot_trace_tempo" {
  for_each = toset(
    split("---",
      file("${path.module}/manifests/adot-trace-tempo.yaml")
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Observer / Trace Destination / Tempo
resource "kubectl_manifest" "observer_adot_traced_tempo" {
  for_each = toset(
    split("---",
      file("${path.module}/manifests/adot-traced-tempo.yaml")
    )
  )
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## EKS Workload
module "eks_workload" {
  providers = {
    kubernetes = kubernetes.workload
  }

  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-work-eks", local.name)
  cluster_version = "1.28"

  vpc_id                          = module.vpc_workload.vpc_id
  subnet_ids                      = module.vpc_workload.private_subnets
  cluster_endpoint_public_access  = true

  manage_aws_auth_configmap = true

  ## Managed Nodegroups
  eks_managed_node_groups = {
    worker = {
      min_size     = 3
      max_size     = 3
      desired_size = 3

      instance_types = ["m5.xlarge"]
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }
    }
  }

  ## Addons
  cluster_addons = {
    coredns = {
      addon_version = "v1.10.1-eksbuild.5"
    }
    vpc-cni = {
      addon_version = "v1.14.1-eksbuild.1"
    }
    kube-proxy = {
      addon_version = "v1.28.1-eksbuild.1"
    }
    adot = {
      addon_version = "v0.90.0-eksbuild.1"
    }
  }

  ## Node Security Group
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
}

## EKS Workload / Cert Manager
resource "helm_release" "workload_cert_manager" {
  provider = helm.workload  

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
    value = module.eks_workload.cluster_name
  }
}

## EKS Workload / Load Balancer Controller
module "irsa_workload_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-workload-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_workload.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "workload_aws_load_balancer_controller" {
  provider = helm.workload  

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"

  set {
    name  = "clusterName"
    value = module.eks_workload.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_workload_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_workload_load_balancer_controller,
  ]
}

## EKS Workload / App Python
data "kubectl_file_documents" "workload_app_python" {
  content = file("${path.module}/manifests/app-python-work.yaml")
}

resource "kubectl_manifest" "workload_app_python" {
  provider = kubectl.workload

  for_each = data.kubectl_file_documents.workload_app_python.manifests
  yaml_body = each.value

  depends_on = [
    module.eks_workload
  ]
}
